//! vanity-generator —— 以太坊靓号地址生成器
//!
//! 模块地图：
//! - [`config`]：config.yaml 解析与严格校验（fatal error 双语输出）
//! - [`matcher`]：前/中/后缀高性能匹配（front/back slice 比较 + memmem SIMD）
//! - [`generator`]：OsRng 熵 → BIP39 → BIP32 → secp256k1 → Keccak → 地址
//! - [`gpg`]：sequoia-openpgp 加密封装（ASCII Armor，兼容 GnuPG）
//! - [`error`]：中英双语错误定义
//! - [`bench`]：criterion 基准共享样本
//!
//! 安全红线（全项目强制）：
//! 1. 禁止任何 unsafe 代码（`#![forbid(unsafe_code)]`）；
//! 2. 熵只允许 OsRng（禁止 ThreadRng/SmallRng 等用户态 PRNG）；
//! 3. 任何日志/输出不得包含助记词或私钥明文；
//! 4. 密码学原语只调权威库，禁止自实现 Keccak/secp256k1/PBKDF2/SHA-512/RIPEMD-160。

#![forbid(unsafe_code)]

pub mod bench;
pub mod config;
pub mod error;
pub mod gpg;
pub mod generator;
pub mod matcher;
