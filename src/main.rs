//! main.rs —— 入口：参数解析 + 配置加载 + rayon 并行调度 + GPG 加密落盘
//!
//! 并行模型（规格 performance_optimization）：
//! - `rayon::scope` 派生 N 个 worker（N = available_parallelism，默认全速）；
//! - worker 各自持有独立的 [`Generator`]（无锁竞争），循环"生成-检查"；
//! - 每次尝试通过 `AtomicU64` 领取全局序号，据此输出进度通知（取模判断，
//!   u64 语义下无溢出风险）；
//! - 命中后经 `crossbeam-channel`（unbounded）发送到主线程，
//!   主线程负责 GPG 加密与落盘，不阻塞计算线程；
//! - 达到 `count` 后主线程置位 `AtomicBool`，worker 检查后退出。

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::unbounded;
use rayon::scope;

use vanity_generator::config::Config;
use vanity_generator::error::VanityError;
use vanity_generator::gpg::GpgEncryptor;
use vanity_generator::generator::Generator;
use vanity_generator::matcher::Matcher;

/// 命令行参数
#[derive(Debug, Parser)]
#[command(
    name = "vanity-generator",
    version,
    about = "以太坊靓号地址生成器（BIP39/BIP32 + OsRng + GPG 加密输出）"
)]
struct Cli {
    /// 指定 config.yaml 路径（默认：可执行文件同目录，或环境变量 VANITY_CONFIG 内容）
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

    // 1. 配置与公钥（CLI > 环境变量 > 同目录文件）
    let gpg_env = std::env::var(vanity_generator::config::ENV_GPG_KEY).ok();
    let cfg = Config::load(cli.config.as_deref(), &exe_dir, gpg_env.as_deref())?;

    // 2. 启动前完成全部昂贵解析（匹配器预构建、公钥 Cert 解析）
    let matcher = Matcher::new(
        cfg.case_sensitive,
        cfg.front.clone(),
        cfg.middle.clone(),
        cfg.back.clone(),
    );
    let gpg_data = match (&cfg.gpg_key_inline, &cfg.gpg_key_path) {
        (Some(content), _) => content.clone().into_bytes(),
        (None, Some(p)) => std::fs::read(p).map_err(|e| {
            VanityError::io(
                format!("failed to read gpg key file {}: {e}", p.display()),
                format!("读取公钥文件 {} 失败：{e}", p.display()),
            )
        })?,
        (None, None) => unreachable!("config 层已保证公钥来源存在"),
    };
    let encryptor = GpgEncryptor::from_bytes(&gpg_data)?;

    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    print_startup(&cfg, &encryptor, threads, &exe_dir);

    // 3. 并行调度
    let started = Instant::now();
    let stopped = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);
    let hits = AtomicU32::new(0);
    let progress_lock = Mutex::new(()); // 进度行原子输出
    let (tx, rx) = unbounded::<vanity_generator::generator::HitRecord>();
    let seq = AtomicU32::new(0);
    let encrypt_err: Mutex<Option<VanityError>> = Mutex::new(None);

    // 直接使用 rayon 全局池（默认 = available_parallelism 线程）：
    // scope 闭包在本线程执行收包循环，N 个 worker 全部进入池内并行。
    // 不自建 ThreadPool：自建池若把闭包 install 到池内线程，
    // 会占掉一个 worker 槽位导致实际并行度少 1（已实测踩坑）。
    {
        // 预先借用/复制跨线程共享的数据（避免 move 闭包逐值搬移）
        let matcher = &matcher;
        let cfg_path = &cfg.path;
        let cfg_indices = &cfg.path_indices;
        let cfg_wc = cfg.word_count;
        let cfg_cs = cfg.case_sensitive;
        let cfg_every = cfg.progress_every;
        scope(|s| {
            for _ in 0..threads {
                let tx = tx.clone();
                let stopped = &stopped;
                let failed = &failed;
                let attempts = &attempts;
                let hits = &hits;
                let progress_lock = &progress_lock;
                s.spawn(move |_| {
                    // 每个 worker 独立持有生成器上下文（无锁竞争）
                    let mut gen = match Generator::new(cfg_wc, cfg_path, cfg_indices, cfg_cs) {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("{e}");
                            failed.store(true, Ordering::Relaxed);
                            stopped.store(true, Ordering::Relaxed);
                            return;
                        }
                    };
                    loop {
                        if stopped.load(Ordering::Relaxed) {
                            return;
                        }
                        // 全局尝试序号：u64 取模判断进度，无溢出风险
                        let ticket = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(every) = cfg_every {
                            if ticket % every == 0 {
                                let _guard = progress_lock.lock().unwrap_or_else(|p| p.into_inner());
                                let elapsed = started.elapsed().as_secs_f64();
                                println!(
                                    "进度：已尝试 {} | 命中 {} | 速率 {:.0}/s | 耗时 {:.0}s",
                                    ticket,
                                    hits.load(Ordering::Relaxed),
                                    ticket as f64 / elapsed.max(f64::EPSILON),
                                    elapsed
                                );
                            }
                        }
                        match gen.try_once(matcher) {
                            Ok(Some(hit)) => {
                                if tx.send(hit).is_err() {
                                    // 主线程已退出（异常终止），停止工作
                                    return;
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                eprintln!("{e}");
                                failed.store(true, Ordering::Relaxed);
                                stopped.store(true, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                });
            }
            drop(tx); // 主线程不再发送，recv 在全部 worker 退出后返回 None

            // 主循环：接收命中 → 加密落盘 → 计数
            let mut encrypted_files: Vec<PathBuf> = Vec::new();
            for hit in rx {
                let n = seq.fetch_add(1, Ordering::Relaxed) + 1;
                match encryptor.encrypt_to_file(&hit, &exe_dir, n) {
                    Ok(path) => {
                        hits.store(n, Ordering::Relaxed);
                        encrypted_files.push(path.clone());
                        println!(
                            "[命中 #{:03}] 地址 {} | 已加密 → {}",
                            n, hit.address, path.display()
                        );
                    }
                    Err(e) => {
                        // 加密失败为致命错误：停止所有 worker 并向主流程传播
                        encrypt_err.lock().unwrap_or_else(|p| p.into_inner()).replace(e);
                        stopped.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                if n >= cfg.count {
                    stopped.store(true, Ordering::Relaxed);
                    break;
                }
            }
            let _ = encrypted_files;
        });
    }

    // 4. 汇总
    let total = attempts.load(Ordering::Relaxed);
    let hit_n = hits.load(Ordering::Relaxed);
    let elapsed = started.elapsed().as_secs_f64();
    if let Some(e) = encrypt_err.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(e.into());
    }
    if failed.load(Ordering::Relaxed) && hit_n < cfg.count {
        // worker 层错误已在输出中打印双语信息；此处保证非零退出码
        return Err(VanityError::internal(
            "worker terminated abnormally; see the bilingual error above.",
            "工作线程异常终止，详见上方的双语错误信息。",
        )
        .into());
    }
    println!(
        "===== 完成 =====\n共尝试 {} 个地址，命中 {} 个，耗时 {:.1}s（平均 {:.0}/s）\n\
         加密文件已输出到 {}",
        total,
        hit_n,
        elapsed,
        total as f64 / elapsed.max(f64::EPSILON),
        exe_dir.display()
    );
    Ok(())
}

/// 可执行文件所在目录（config.yaml 与输出文件的默认位置）
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

/// 启动信息（中文；不输出任何敏感内容）
fn print_startup(cfg: &Config, encryptor: &GpgEncryptor, threads: usize, exe_dir: &std::path::Path) {
    let entropy_bits = match cfg.word_count {
        12 => 128,
        18 => 192,
        _ => 256,
    };
    let mut rule = Vec::new();
    if let Some(f) = &cfg.front {
        rule.push(format!("前缀 {}", String::from_utf8_lossy(f)));
    }
    if let Some(m) = &cfg.middle {
        rule.push(format!("中缀 {}", String::from_utf8_lossy(m)));
    }
    if let Some(b) = &cfg.back {
        rule.push(format!("后缀 {}", String::from_utf8_lossy(b)));
    }
    println!("===== vanity-generator 启动 =====");
    println!(
        "助记词长度 : {} 词（{} 位熵）",
        cfg.word_count, entropy_bits
    );
    println!(
        "靓号规则   : {}（大小写敏感：{}）",
        rule.join(" + "),
        if cfg.case_sensitive { "是" } else { "否" }
    );
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
        "进度通知   : {}",
        cfg.progress_every
            .map_or_else(|| "已禁用".to_string(), |n| format!("每 {n} 次尝试"))
    );
    let key_src = cfg
        .gpg_key_path
        .as_ref()
        .map_or_else(
            || format!("环境变量 {}", vanity_generator::config::ENV_GPG_KEY),
            |p| format!("文件 {}", p.display()),
        );
    println!(
        "GPG 公钥   : {}（可用加密子密钥 {} 个）",
        key_src,
        encryptor.usable_keys()
    );
    println!("工作线程   : {threads}");
    println!("输出目录   : {}", exe_dir.display());
}
