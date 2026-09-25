//! gpg.rs —— OpenPGP 加密封装（sequoia-openpgp，输出与 GnuPG 兼容）
//!
//! 职责（规格 gpg_encryption，第 4 步实现）：
//! 1. 解析 config 指定的 ASCII armor 公钥（`sequoia_openpgp::Cert`，
//!    任何后缀的纯文本公钥均可，首行 armor 头已在 config 层校验）；
//! 2. 按固定格式构造明文：
//!    ```text
//!    Address: 0x...
//!    Path: m/44'/60'/0'/0/0
//!    Mnemonic: word1 ... wordN
//!    Created: 2026-09-25T12:00:00Z
//!    ```
//! 3. 用公钥加密，输出 ASCII Armor（与 `gpg -a` 输出兼容）；
//! 4. 落盘 `vanity_YYYYMMDD_HHMMSS_NNN.asc`（NNN 为本次运行序号），
//!    放在可执行文件同目录等待用户提取；
//! 5. 加密成功后立即 zeroize 明文缓冲区。
//!
//! 加密完全在本地完成，无需用户提供私钥；
//! 公钥文件格式兼容 GnuPG 导出的任何 ASCII armor 公钥。

use std::path::{Path, PathBuf};

use crate::error::VanityError;
use crate::generator::HitRecord;

/// GPG 加密器：持有已解析的公钥证书
#[derive(Debug)]
pub struct GpgEncryptor {
    /// 公钥文件路径（Cert 解析在第 4 步接入）
    key_path: PathBuf,
}

impl GpgEncryptor {
    /// 从公钥文件构造加密器。
    ///
    /// 第 4 步实现：解析 Cert + 按策略选取可用加密 subkey；
    /// 骨架阶段仅记录路径。
    pub fn new(key_path: &Path) -> Result<Self, VanityError> {
        Ok(Self {
            key_path: key_path.to_path_buf(),
        })
    }

    /// 公钥路径（骨架期占位字段读取，保留字段语义）
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// 加密并落盘一条命中记录。
    ///
    /// 返回落盘文件路径；成功后明文缓冲已零化。
    /// `seq`：本次运行内序号（从 1 开始，文件名 NNN 三位零填充）。
    pub fn encrypt_to_file(
        &self,
        _record: &HitRecord,
        _out_dir: &Path,
        _seq: u32,
    ) -> Result<PathBuf, VanityError> {
        Err(VanityError::not_implemented("gpg::encrypt_to_file"))
    }
}
