//! matcher.rs —— 靓号前/中/后缀高性能匹配
//!
//! 性能分层设计（对应规格 matching_rules）：
//! 1. 输入为去掉 `0x` 的 40 字节小写 hex 字符串（调用方栈上缓冲），
//!    避免 0x 前缀带来的无意义偏移；
//! 2. front / back：slice 前后缀比较，编译为 memcmp，长度不等立即 false；
//! 3. middle：`memchr::memmem`（x86_64 上 SSE2 基线，运行时自动检测升级
//!    AVX2），禁止 `String::contains`（不走 SIMD 路径）；
//!    Matcher 构造时预建 `Finder`，摊销搜索器构造成本；
//! 4. 判定顺序 front → back → middle：更便宜的剪枝放在前面，
//!    未命中直接短路返回；
//! 5. 命中后由上层计算 EIP-55 大小写校验和，匹配全程使用小写。
//!
//! 大小写敏感模式（case_sensitive = true）：
//! - needle 保留用户书写的大小写原样；
//! - 比对目标是地址的 EIP-55 校验和形式（由调用方传入第二缓冲），
//!   即 front: "AaAaAa" 只匹配校验和形式恰好为 0xAaAaAa 的地址，
//!   0xaaaaaa 不命中。数字字符大小写不变。

use memchr::memmem;

/// 靓号匹配器：构造一次，多线程共享（所有字段只读）
#[derive(Debug)]
pub struct Matcher {
    /// 大小写敏感（true 时比对 EIP-55 校验和形式）
    case_sensitive: bool,
    /// 前缀 needle（不敏感=小写；敏感=原样）
    front: Option<Vec<u8>>,
    /// 后缀 needle
    back: Option<Vec<u8>>,
    /// 中缀搜索器（预构建，SIMD 加速；`into_owned` 后持有 needle 所有权）
    middle: Option<memmem::Finder<'static>>,
    /// 原始中缀 needle（供期望次数估算与文本描述，不参与匹配）
    middle_raw: Option<Vec<u8>>,
}

impl Matcher {
    /// 由归一化后的 needle 构造。
    /// 任一参数传 `None` 表示该条件不参与匹配；空 needle 视为未定义。
    pub fn new(
        case_sensitive: bool,
        front: Option<Vec<u8>>,
        middle: Option<Vec<u8>>,
        back: Option<Vec<u8>>,
    ) -> Self {
        let middle_raw = middle.clone().filter(|m| !m.is_empty());
        Self {
            case_sensitive,
            front: front.filter(|f| !f.is_empty()),
            back: back.filter(|b| !b.is_empty()),
            // 预构建 Finder 并转入 owned（'static），避免热循环重建搜索器
            middle: middle
                .filter(|m| !m.is_empty())
                .map(|m| memmem::Finder::new(m.as_slice()).into_owned()),
            // 原始中缀 needle（供期望次数估算与文本描述）
            middle_raw,
        }
    }

    /// 大小写敏感模式
    pub fn case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// 判定地址是否命中。
    ///
    /// - `hex40_lower`：40 字节小写 hex（不敏感模式的比对目标）；
    /// - `hex40_checksum`：40 字节 EIP-55 校验和形式（敏感模式必须提供）。
    #[inline]
    pub fn matches(&self, hex40_lower: &[u8], hex40_checksum: Option<&[u8]>) -> bool {
        let hay: &[u8] = if self.case_sensitive {
            hex40_checksum.expect("大小写敏感模式必须提供 EIP-55 校验和形式")
        } else {
            hex40_lower
        };
        // front：最便宜的剪枝
        if let Some(f) = &self.front {
            if !hay.starts_with(f) {
                return false;
            }
        }
        // back：尾部对齐
        if let Some(b) = &self.back {
            if !hay.ends_with(b) {
                return false;
            }
        }
        // middle：SIMD 子串搜索
        if let Some(m) = &self.middle {
            if m.find(hay).is_none() {
                return false;
            }
        }
        true
    }

    /// 期望尝试次数估计（幂律近似，用于启动提示与可行性预估）。
    ///
    /// - front/back：每位 hex 字符贡献 16 倍；
    /// - middle：按 (40-len+1) 个可能起点近似；
    /// - 大小写敏感模式下每个字母位额外贡献 2 倍（EIP-55 案例约随机）。
    pub fn expected_attempts(&self) -> f64 {
        let mut p = 1.0f64;
        let mut hex_len = 0.0f64;
        let mut letters = 0usize;
        if let Some(f) = &self.front {
            hex_len += f.len() as f64;
            letters += f.iter().filter(|b| b.is_ascii_alphabetic()).count();
        }
        if let Some(b) = &self.back {
            hex_len += b.len() as f64;
            letters += b.iter().filter(|b| b.is_ascii_alphabetic()).count();
        }
        p /= 16f64.powf(hex_len);
        if let Some(m) = &self.middle_raw {
            let n = m.len() as f64;
            // 子串在 40 字符地址中出现的概率 ≈ (41-n) × 16^-n（上限 1）
            p *= ((41.0 - n).max(1.0) / 16f64.powf(n)).min(1.0);
            letters += m.iter().filter(|b| b.is_ascii_alphabetic()).count();
        }
        if self.case_sensitive {
            p /= 2f64.powi(letters as i32);
        }
        1.0 / p.max(1e-300)
    }

    /// 规则文本描述（如"前缀 ab + 后缀 88"，供启动摘要）
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(f) = &self.front {
            parts.push(format!("前缀 {}", String::from_utf8_lossy(f)));
        }
        if let Some(m) = &self.middle_raw {
            parts.push(format!("包含 {}", String::from_utf8_lossy(m)));
        }
        if let Some(b) = &self.back {
            parts.push(format!("后缀 {}", String::from_utf8_lossy(b)));
        }
        parts.join(" + ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 40 字节小写 hex 测试地址（4 + 16 + 16 + 4 = 40）
    const HEX40: &[u8; 40] = b"88880123456789abcdef0123456789abcdef1234";

    #[test]
    fn front_命中() {
        // 规格：front="8888" 匹配 "0x8888..." 为 true
        let m = Matcher::new(false, Some(b"8888".to_vec()), None, None);
        assert!(m.matches(HEX40, None));
    }

    #[test]
    fn front_未命中() {
        // 规格：front="8888" 匹配 "0x18888..." 为 false（首字符 1 ≠ 8）
        let hex: &[u8; 40] = b"18880123456789abcdef0123456789abcdef1234";
        let m = Matcher::new(false, Some(b"8888".to_vec()), None, None);
        assert!(!m.matches(hex, None));
    }

    #[test]
    fn back_命中与未命中() {
        let m = Matcher::new(false, None, None, Some(b"1234".to_vec()));
        assert!(m.matches(HEX40, None)); // 尾部正好是 1234
        let m2 = Matcher::new(false, None, None, Some(b"8888".to_vec()));
        assert!(!m2.matches(HEX40, None)); // 尾部不是 8888
    }

    #[test]
    fn middle_命中() {
        // 规格：middle="8888" 匹配 "0x1238888..." 为 true（任意位置包含）
        let m = Matcher::new(false, None, Some(b"8888".to_vec()), None);
        let hex: &[u8; 40] = b"1238888456789abcdef0123456789abcdef01234";
        assert!(m.matches(hex, None));
        assert!(m.matches(HEX40, None)); // 开头包含也算命中
    }

    #[test]
    fn middle_未命中() {
        let m = Matcher::new(false, None, Some(b"9999".to_vec()), None);
        assert!(!m.matches(HEX40, None));
    }

    #[test]
    fn 复合条件_必须同时满足() {
        let m = Matcher::new(
            false,
            Some(b"8888".to_vec()),
            Some(b"abcd".to_vec()),
            Some(b"1234".to_vec()),
        );
        assert!(m.matches(HEX40, None));
        // front 命中但 back 不满足 → false
        let m2 = Matcher::new(false, Some(b"8888".to_vec()), None, Some(b"9999".to_vec()));
        assert!(!m2.matches(HEX40, None));
        // back 命中但 front 不满足 → false
        let m3 = Matcher::new(false, Some(b"9999".to_vec()), None, Some(b"1234".to_vec()));
        assert!(!m3.matches(HEX40, None));
    }

    #[test]
    fn needle_长于地址_直接未命中() {
        let m = Matcher::new(false, None, Some(b"8888".to_vec()), None);
        let short: &[u8] = b"8888"; // 不足 40 字节的异常输入也应安全
        assert!(m.matches(short, None)); // 子串包含，依然成立
        let m2 = Matcher::new(false, Some(b"8888".repeat(11).to_vec()), None, None); // 44 > 40
        assert!(!m2.matches(HEX40, None));
    }

    #[test]
    fn 空_matcher_匹配一切() {
        // Config 层保证至少定义一个条件，此处仅验证 matcher 自身语义
        let m = Matcher::new(false, None, None, None);
        assert!(m.matches(HEX40, None));
    }

    #[test]
    fn 空_needle_视为未定义() {
        let m = Matcher::new(false, Some(Vec::new()), None, None);
        assert!(m.matches(HEX40, None));
    }

    /// 大小写敏感：比对目标是 EIP-55 校验和形式
    #[test]
    fn 大小写敏感_按校验和形式匹配() {
        // 用户需求示例：front: AaAaAa 只匹配校验和形式 0xAaAaAa…，0xaaaaaa… 不命中
        let m = Matcher::new(true, Some(b"AaAaAa".to_vec()), None, None);
        // 栈上缓冲样本：40 字节（6 + 30 + 4）
        let checksummed: &[u8; 40] = b"AaAaAa0123456789abcdef0123456789abcd1234";
        assert!(m.matches(b"aaaaaa0123456789abcdef0123456789abcd1234", Some(checksummed)));

        // 校验和形式为 aaaaaa…（全小写）→ 不命中
        let lower_only: &[u8; 40] = b"aaaaaa0123456789abcdef0123456789abcd1234";
        assert!(!m.matches(lower_only, Some(lower_only)));

        // 大小写敏感下混入错误大小写 → 不命中
        let wrong_case: &[u8; 40] = b"AAAAAA0123456789abcdef0123456789abcd1234";
        assert!(!m.matches(b"aaaaaa0123456789abcdef0123456789abcd1234", Some(wrong_case)));
    }

    /// 大小写不敏感：needle 统一小写后比对小写形式，校验和形式不参与
    #[test]
    fn 大小写不敏感_忽略校验和形式() {
        let m = Matcher::new(false, Some(b"aaaaaa".to_vec()), None, None);
        let lower: &[u8; 40] = b"aaaaaa0123456789abcdef0123456789abcd1234";
        // 即使传了校验和形式，不敏感模式也只用小写形式
        let checksummed: &[u8; 40] = b"AAAAAA0123456789abcdef0123456789abcd1234";
        assert!(m.matches(lower, Some(checksummed)));
    }

    /// 大小写敏感模式下数字不受影响
    #[test]
    fn 大小写敏感_数字不受影响() {
        let m = Matcher::new(true, Some(b"8888".to_vec()), None, None);
        assert!(m.matches(HEX40, Some(HEX40)));
    }

    /// 期望尝试次数估算
    #[test]
    fn 期望次数_估算() {
        // 2 位前缀 → 256
        let m = Matcher::new(false, Some(b"ab".to_vec()), None, None);
        assert!((m.expected_attempts() - 256.0).abs() < 1e-6);
        // 4 位前缀 → 65536
        let m = Matcher::new(false, Some(b"8888".to_vec()), None, None);
        assert!((m.expected_attempts() - 65_536.0).abs() < 1e-3);
        // 前缀+后缀联合 → 16^8
        let m = Matcher::new(false, Some(b"8888".to_vec()), None, Some(b"8888".to_vec()));
        assert!((m.expected_attempts() - 16f64.powf(8.0)).abs() < 1e6);
        // 大小写敏感 4 字母前缀 → 16^4 × 2^4
        let m = Matcher::new(true, Some(b"AaBb".to_vec()), None, None);
        assert!((m.expected_attempts() - 16f64.powf(4.0) * 16.0).abs() < 1e-3);
    }

    /// 规则文本描述
    #[test]
    fn 规则描述() {
        let m = Matcher::new(false, Some(b"ab".to_vec()), Some(b"77".to_vec()), Some(b"88".to_vec()));
        assert_eq!(m.describe(), "前缀 ab + 包含 77 + 后缀 88");
    }
}
