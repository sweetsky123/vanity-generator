//! criterion 基准入口。
//!
//! 当前覆盖：
//! a. 匹配器核心（front / back / middle / 复合剪枝路径）；
//! b. 单线程全链路（OsRng 熵 → 地址，性能基准的吞吐基线）；
//! c. 多线程吞吐（2 / 4 / 8 线程，用于验证并行扩展性 ≥ 0.7×线程数）。
//!
//! 运行：`cargo bench`（README 性能一节以多轮中位数为准）。

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use vanity_generator::bench::{SAMPLE_HEX40, SAMPLE_HEX40_MISS};
use vanity_generator::generator::Generator;
use vanity_generator::matcher::Matcher;

/// 默认派生路径 m/44'/60'/0'/0/0
const PATH_INDICES: [u32; 5] = [0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 0];

fn bench_matcher(c: &mut Criterion) {
    // front 命中（最便宜的剪枝路径）
    {
        let m = Matcher::new(false, Some(b"8888".to_vec()), None, None);
        c.bench_function("matcher/front_hit", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40.as_slice()), None))
        });
    }
    // front 未命中（首字符即失败 —— 热循环中最常见路径）
    {
        let m = Matcher::new(false, Some(b"8888".to_vec()), None, None);
        c.bench_function("matcher/front_miss", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40_MISS.as_slice()), None))
        });
    }
    // back 命中（尾部对齐比较）
    {
        let m = Matcher::new(false, None, None, Some(b"8888".to_vec()));
        c.bench_function("matcher/back_hit", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40.as_slice()), None))
        });
    }
    // middle 命中（memmem SIMD 子串搜索）
    {
        let m = Matcher::new(false, None, Some(b"8888".to_vec()), None);
        c.bench_function("matcher/middle_hit", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40.as_slice()), None))
        });
    }
    // 复合条件全命中（front → back → middle 逐级剪枝）
    {
        let m = Matcher::new(
            false,
            Some(b"8888".to_vec()),
            Some(b"aaaa".to_vec()),
            Some(b"8888".to_vec()),
        );
        c.bench_function("matcher/composite_hit", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40.as_slice()), None))
        });
    }
    // 大小写敏感：额外计算 EIP-55 校验和形式
    {
        let m = Matcher::new(true, Some(b"8888".to_vec()), None, None);
        c.bench_function("matcher/case_sensitive_hit", |b| {
            b.iter(|| {
                let mut checksum = [0u8; 40];
                checksum.copy_from_slice(black_box(SAMPLE_HEX40.as_slice()));
                m.matches(black_box(SAMPLE_HEX40.as_slice()), Some(&checksum))
            })
        });
    }
}

/// 全链路吞吐：每个 iters 周期内线程组共执行 iters × PER_BATCH 次生成-检查
const PER_BATCH: u64 = 64;

fn bench_pipeline_threads(c: &mut Criterion, threads: usize) {
    let mut group = c.benchmark_group(format!("pipeline/{threads}thread"));
    group.throughput(criterion::Throughput::Elements(PER_BATCH));
    group.bench_function("gen_and_match", |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            let total = iters * PER_BATCH;
            let done = AtomicU64::new(0);
            std::thread::scope(|s| {
                for _ in 0..threads {
                    s.spawn(|| {
                        let matcher = Matcher::new(false, Some(b"ffff".to_vec()), None, None);
                        let mut g = Generator::new(24, "m/44'/60'/0'/0/0", &PATH_INDICES, false)
                            .unwrap();
                        // ffff 前缀实际命中概率 2^-196，以下循环全部走未命中路径
                        while done.fetch_add(1, Ordering::Relaxed) < total {
                            let _ = g.try_once(&matcher);
                        }
                    });
                }
            });
            start.elapsed()
        })
    });
    group.finish();
}

fn bench_pipeline(c: &mut Criterion) {
    // ---- 分阶段剖析（性能瓶颈定位）----
    // 阶段 1：BIP39 种子（PBKDF2-HMAC-SHA512 × 2048 轮，历史瓶颈）
    {
        use bip39::{Language, Mnemonic};
        let m = Mnemonic::from_entropy_in(Language::English, &[7u8; 32]).unwrap();
        c.bench_function("pipeline/stage1_seed_pbkdf2", |b| {
            b.iter(|| m.to_seed(black_box("")))
        });
    }
    // 阶段 2：BIP32 派生 m/44'/60'/0'/0/0（3 次 hardened + 2 次 normal CKD）
    {
        use bip39::{Language, Mnemonic};
        let seed = Mnemonic::from_entropy_in(Language::English, &[7u8; 32])
            .unwrap()
            .to_seed("");
        c.bench_function("pipeline/stage2_bip32_derive", |b| {
            b.iter(|| {
                let mut x = bip32::XPrv::new(black_box(seed.as_slice())).unwrap();
                for idx in PATH_INDICES {
                    let hard = (idx & 0x8000_0000) != 0;
                    let cn = bip32::ChildNumber::new(idx & 0x7FFF_FFFF, hard).unwrap();
                    x = x.derive_child(cn).unwrap();
                }
                black_box(x.to_bytes())
            })
        });
    }
    // 全链路（OsRng 熵 → 匹配，性能基准的吞吐基线）
    bench_pipeline_threads(c, 1);
    bench_pipeline_threads(c, 2);
    bench_pipeline_threads(c, 4);
    bench_pipeline_threads(c, 8);
}

criterion_group!(benches, bench_matcher, bench_pipeline);
criterion_main!(benches);
