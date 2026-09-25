//! criterion 基准入口。
//!
//! 当前（第 1 步）：匹配器核心（front / back / middle / 复合剪枝路径）；
//! 第 7-8 步补充：全链路（熵→助记词→派生→地址）、多线程吞吐
//! （1/2/4/8/N = available_parallelism）。
//!
//! 运行：`cargo bench`（输出 ops/s，README 性能一节以 3 轮中位数为准）。

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use vanity_generator::bench::{SAMPLE_HEX40, SAMPLE_HEX40_MISS};
use vanity_generator::matcher::Matcher;

fn bench_matcher(c: &mut Criterion) {
    // front 命中（最便宜的剪枝路径）
    {
        let m = Matcher::new(Some(b"8888".to_vec()), None, None);
        c.bench_function("matcher/front_hit", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40.as_slice())))
        });
    }
    // front 未命中（首字符即失败 —— 热循环中最常见路径）
    {
        let m = Matcher::new(Some(b"8888".to_vec()), None, None);
        c.bench_function("matcher/front_miss", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40_MISS.as_slice())))
        });
    }
    // back 命中（尾部对齐比较）
    {
        let m = Matcher::new(None, None, Some(b"8888".to_vec()));
        c.bench_function("matcher/back_hit", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40.as_slice())))
        });
    }
    // middle 命中（memmem SIMD 子串搜索）
    {
        let m = Matcher::new(None, Some(b"8888".to_vec()), None);
        c.bench_function("matcher/middle_hit", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40.as_slice())))
        });
    }
    // 复合条件全命中（front → back → middle 逐级剪枝）
    {
        let m = Matcher::new(
            Some(b"8888".to_vec()),
            Some(b"aaaa".to_vec()),
            Some(b"8888".to_vec()),
        );
        c.bench_function("matcher/composite_hit", |b| {
            b.iter(|| m.matches(black_box(SAMPLE_HEX40.as_slice())))
        });
    }
}

criterion_group!(benches, bench_matcher);
criterion_main!(benches);
