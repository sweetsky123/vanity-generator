//! perf_probe —— 性能剖析探针（仅本地诊断用，不进入发布流程）
//!
//! 与正式二进制完全相同的 release profile（fat LTO）下，
//! 逐阶段计时"生成-检查"流水线，定位性能瓶颈。
//!
//! 运行：cargo run --release --example perf_probe

use std::time::Instant;

use bip32::{ChildNumber, XPrv};
use bip39::{Language, Mnemonic};
use vanity_generator::generator::Generator;
use vanity_generator::matcher::Matcher;

const PATH_INDICES: [u32; 5] = [0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 0];

fn main() {
    let n = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(200);
    let mut entropies = vec![[0u8; 32]; n as usize];
    for (i, e) in entropies.iter_mut().enumerate() {
        e[0] = (i >> 8) as u8;
        e[1] = i as u8;
    }

    // 阶段 0：熵 → 助记词（from_entropy_in）
    let t0 = Instant::now();
    let mnemonics: Vec<Mnemonic> = entropies
        .iter()
        .map(|e| Mnemonic::from_entropy_in(Language::English, e).unwrap())
        .collect();
    let d0 = t0.elapsed().as_secs_f64() * 1000.0 / n as f64;
    println!("阶段0 熵→助记词        : {d0:>8.4} ms/次");

    // 阶段 1：助记词 → 种子（PBKDF2 × 2048 轮）
    let t1 = Instant::now();
    let seeds: Vec<_> = mnemonics.iter().map(|m| m.to_seed("")).collect();
    let d1 = t1.elapsed().as_secs_f64() * 1000.0 / n as f64;
    println!("阶段1 种子 PBKDF2      : {d1:>8.4} ms/次");

    // 阶段 2：种子 → BIP32 派生（XPrv + 5 层）
    let t2 = Instant::now();
    for seed in &seeds {
        let mut x = XPrv::new(seed.as_slice()).unwrap();
        for idx in PATH_INDICES {
            let hard = (idx & 0x8000_0000) != 0;
            let cn = ChildNumber::new(idx & 0x7FFF_FFFF, hard).unwrap();
            x = x.derive_child(cn).unwrap();
        }
        let _ = x.to_bytes();
    }
    let d2 = t2.elapsed().as_secs_f64() * 1000.0 / n as f64;
    println!("阶段2 BIP32 派生       : {d2:>8.4} ms/次");

    // 全链路（与真实 worker 相同的 try_once 循环形状）
    let matcher = Matcher::new(false, Some(b"ffff".to_vec()), None, None);
    let mut g = Generator::new(24, "m/44'/60'/0'/0/0", &PATH_INDICES, false).unwrap();
    let t3 = Instant::now();
    for _ in 0..n {
        let _ = g.try_once(&matcher);
    }
    let d3 = t3.elapsed().as_secs_f64() * 1000.0 / n as f64;
    println!("全链路 try_once        : {d3:>8.4} ms/次  ({:.0}/s 单线程)", 1000.0 / d3);

    let sum = d0 + d1 + d2;
    println!("---- 阶段0-2 合计 {sum:.4} ms，全链路 {d3:.4} ms，未解释差额 {:.4} ms ----", (d3 - sum).max(0.0));
}
