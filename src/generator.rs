//! generator.rs —— 助记词生成 + BIP32 派生 + secp256k1 + 地址计算
//!
//! 单次"生成-检查"流水线（规格 generation_pipeline，第 3 步实现）：
//! 1. `OsRng`（rand::rngs::OsRng）产生 16 / 24 / 32 字节熵（对应 12/18/24 词）；
//! 2. `bip39::Mnemonic::from_entropy_in(Language::English, entropy)`
//!    —— 英文词表（BIP39 标准词表）；
//! 3. `Mnemonic -> seed -> ExtendedPrivKey(XPrv) -> 按 path 逐层派生`
//!    （bip32 crate，rust-bitcoin 官方生态）；
//! 4. `k256::SecretKey::from_slice` 校验私钥在 [1, n-1] 范围内；
//! 5. 私钥 → 公钥（secp256k1 点乘，k256）；
//! 6. 对未压缩公钥（64 字节，无 04 前缀）做 Keccak-256（tiny-keccak）；
//! 7. 取后 20 字节作为地址，小写 hex 编码到栈上 [u8; 40]；
//! 8. 匹配器判定：命中进入 GPG 加密流程，未命中 zeroize 后丢弃全部敏感数据。
//!
//! 安全红线：
//! - 严禁 ThreadRng / SmallRng / 任何非 OsRng 熵源生成助记词（生产路径）；
//! - 匹配失败时不得保留私钥或助记词（Zeroizing 包裹）；
//! - 任何 console 输出禁止包含助记词/私钥明文。

use zeroize::Zeroizing;

use crate::error::VanityError;
use crate::matcher::Matcher;

/// 一次命中的完整记录。
///
/// 仅在匹配命中后构造；加密落盘后调用方应立即让其在作用域结束时
/// 释放（内部敏感字段均 Zeroizing 包裹，drop 时擦除）。
#[derive(Debug)]
pub struct HitRecord {
    /// EIP-55 大小写校验和地址（含 0x 前缀）
    pub address: String,
    /// 派生路径（用户配置原样写法）
    pub path: String,
    /// 助记词（敏感：Zeroizing 防止释放后内存残留）
    pub mnemonic: Zeroizing<String>,
    /// 命中时间（UTC ISO-8601，Z 结尾）
    pub created: String,
}

/// 生成器上下文：每个工作线程独立持有一份，避免锁竞争
///（对应规格算法层优化要求）。
///
/// 第 3 步实现；骨架阶段构造与单次尝试均返回 not_implemented。
#[derive(Debug)]
pub struct Generator {
    word_count: u8,
    path_indices: Vec<u32>,
}

impl Generator {
    /// 构造生成器：`path_indices` 来自 [`crate::config::Config::path_indices`]
    pub fn new(word_count: u8, path_indices: &[u32]) -> Result<Self, VanityError> {
        // 第 3 步：初始化 k256 上下文与栈上工作缓冲
        Ok(Self {
            word_count,
            path_indices: path_indices.to_vec(),
        })
    }

    /// 词数（骨架期占位字段读取，保留字段语义）
    pub fn word_count(&self) -> u8 {
        self.word_count
    }

    /// 派生层级数（骨架期占位字段读取，保留字段语义）
    pub fn depth(&self) -> usize {
        self.path_indices.len()
    }

    /// 单次"生成-检查"：返回 `Some(HitRecord)` 表示命中。
    ///
    /// 第 3 步实现完整流水线；未命中时所有敏感缓冲已零化。
    pub fn try_once(&mut self, _matcher: &Matcher) -> Result<Option<HitRecord>, VanityError> {
        Err(VanityError::not_implemented("generator::try_once"))
    }
}
