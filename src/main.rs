//! main.rs —— 入口：参数解析 + 配置加载与校验 +（后续步骤）并行调度
//!
//! 当前（第 1 步）：加载并校验 config.yaml，打印生效配置摘要；
//! 第 5 步接入 rayon 并行调度 + GPG 加密落盘。

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use vanity_generator::config::Config;
use vanity_generator::error::VanityError;

/// 命令行参数
#[derive(Debug, Parser)]
#[command(
    name = "vanity-generator",
    version,
    about = "以太坊靓号地址生成器（BIP39/BIP32 + OsRng + GPG 加密输出）"
)]
struct Cli {
    /// 指定 config.yaml 路径（默认：可执行文件同目录的 config.yaml）
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // VanityError 按统一双语格式输出；其余错误给出通用双语包装
            match err.downcast_ref::<VanityError>() {
                Some(v) => eprintln!("{v}"),
                None => eprintln!(
                    "[ERROR / 错误]\nEN: unexpected internal error: {err:?}\n\
                     CN: 发生未预期的内部错误：{err:?}"
                ),
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let exe_dir = exe_dir()?;
    let config_path = cli.config.unwrap_or_else(|| exe_dir.join("config.yaml"));
    let cfg = Config::load(&config_path, &exe_dir)?;

    // 打印生效配置（中文交互文案；不含任何敏感信息）
    println!("===== 配置校验通过 =====");
    println!(
        "助记词长度 : {} 词（{} 位熵）",
        cfg.word_count,
        entropy_bits(cfg.word_count)
    );
    println!("靓号规则   : {}", rule_summary(&cfg));
    println!(
        "派生路径   : {}（{} 层，其中 hardened {} 层）",
        cfg.path,
        cfg.path_indices.len(),
        cfg.path_indices
            .iter()
            .filter(|i| (*i & 0x8000_0000) != 0)
            .count()
    );
    println!("目标数量   : {}", cfg.count);
    println!(
        "GPG 公钥   : {}（armor 首行校验通过）",
        cfg.gpg_key_file.display()
    );
    println!("[骨架阶段] 并行生成与 GPG 加密将在后续步骤实现，本次仅校验配置。");
    Ok(())
}

/// 可执行文件所在目录
fn exe_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|e| {
        VanityError::io(
            format!("failed to locate the running executable: {e}. Please run the binary directly."),
            format!("无法定位当前可执行文件：{e}。请直接运行本程序。"),
        )
    })?;
    Ok(exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".")))
}

/// 词数对应的熵位数（BIP39）
fn entropy_bits(word_count: u8) -> u16 {
    match word_count {
        12 => 128,
        18 => 192,
        24 => 256,
        _ => 0,
    }
}

/// 靓号规则摘要（用于启动日志，非敏感）
fn rule_summary(cfg: &Config) -> String {
    let mut parts = Vec::new();
    if let Some(f) = &cfg.front {
        parts.push(format!("前缀 {}", String::from_utf8_lossy(f)));
    }
    if let Some(m) = &cfg.middle {
        parts.push(format!("中缀 {}", String::from_utf8_lossy(m)));
    }
    if let Some(b) = &cfg.back {
        parts.push(format!("后缀 {}", String::from_utf8_lossy(b)));
    }
    parts.join(" + ")
}
