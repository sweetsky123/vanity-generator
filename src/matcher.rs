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

use memchr::memmem;

/// 靓号匹配器：构造一次，多线程共享（所有字段只读）
#[derive(Debug)]
pub struct Matcher {
    /// 前缀 needle（小写 hex 字节）
    front: Option<Vec<u8>>,
    /// 后缀 needle（小写 hex 字节）
    back: Option<Vec<u8>>,
    /// 中缀搜索器（预构建，SIMD 加速；`into_owned` 后持有 needle 所有权）
    middle: Option<memmem::Finder<'static>>,
}

impl Matcher {
    /// 由归一化后的（小写 hex）needle 构造。
    /// 任一参数传 `None` 表示该条件不参与匹配；空 needle 视为未定义。
    pub fn new(
        front: Option<Vec<u8>>,
        middle: Option<Vec<u8>>,
        back: Option<Vec<u8>>,
    ) -> Self {
        Self {
            front: front.filter(|f| !f.is_empty()),
            back: back.filter(|b| !b.is_empty()),
            // 预构建 Finder 并转入 owned（'static），避免热循环重建搜索器
            middle: middle
                .filter(|m| !m.is_empty())
                .map(|m| memmem::Finder::new(m.as_slice()).into_owned()),
        }
    }

    /// 判定 40 字节小写 hex 地址是否命中。
    ///
    /// 复合条件的剪枝顺序：front（最便宜的逐字节比较）→
    /// back（尾部对齐比较）→ middle（memmem SIMD 子串搜索）。
    #[inline]
    pub fn matches(&self, hex40: &[u8]) -> bool {
        if let Some(f) = &self.front {
            // 长度不等立即 false；等长则逐字节比较（memcmp 语义）
            if !hex40.starts_with(f) {
                return false;
            }
        }
        if let Some(b) = &self.back {
            // 尾部对齐 slice 比较
            if !hex40.ends_with(b) {
                return false;
            }
        }
        if let Some(m) = &self.middle {
            // memmem 子串搜索：40 字节干草堆视为常数复杂度
            if m.find(hex40).is_none() {
                return false;
            }
        }
        true
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
        let m = Matcher::new(Some(b"8888".to_vec()), None, None);
        assert!(m.matches(HEX40));
    }

    #[test]
    fn front_未命中() {
        // 规格：front="8888" 匹配 "0x18888..." 为 false（首字符 1 ≠ 8）
        let hex: &[u8; 40] = b"18880123456789abcdef0123456789abcdef1234";
        let m = Matcher::new(Some(b"8888".to_vec()), None, None);
        assert!(!m.matches(hex));
    }

    #[test]
    fn back_命中与未命中() {
        let m = Matcher::new(None, None, Some(b"1234".to_vec()));
        assert!(m.matches(HEX40)); // 尾部正好是 1234
        let m2 = Matcher::new(None, None, Some(b"8888".to_vec()));
        assert!(!m2.matches(HEX40)); // 尾部不是 8888
    }

    #[test]
    fn middle_命中() {
        // 规格：middle="8888" 匹配 "0x1238888..." 为 true（任意位置包含）
        let m = Matcher::new(None, Some(b"8888".to_vec()), None);
        let hex: &[u8; 40] = b"1238888456789abcdef0123456789abcdef01234";
        assert!(m.matches(hex));
        assert!(m.matches(HEX40)); // 开头包含也算命中
    }

    #[test]
    fn middle_未命中() {
        let m = Matcher::new(None, Some(b"9999".to_vec()), None);
        assert!(!m.matches(HEX40));
    }

    #[test]
    fn 复合条件_必须同时满足() {
        // front + middle + back 全部同时定义且全部满足
        let m = Matcher::new(
            Some(b"8888".to_vec()),
            Some(b"abcdef".to_vec()),
            Some(b"1234".to_vec()),
        );
        assert!(m.matches(HEX40));
        // front 命中但 back 不满足 → false
        let m2 = Matcher::new(Some(b"8888".to_vec()), None, Some(b"9999".to_vec()));
        assert!(!m2.matches(HEX40));
        // back 命中但 front 不满足 → false
        let m3 = Matcher::new(Some(b"9999".to_vec()), None, Some(b"1234".to_vec()));
        assert!(!m3.matches(HEX40));
    }

    #[test]
    fn needle_长于地址_直接未命中() {
        let m = Matcher::new(None, Some(b"8888".to_vec()), None);
        let short: &[u8] = b"8888"; // 不足 40 字节的异常输入也应安全
        assert!(m.matches(short)); // 子串包含，依然成立
        let m2 = Matcher::new(Some(b"8888".repeat(11).to_vec()), None, None); // 44 > 40
        assert!(!m2.matches(HEX40));
    }

    #[test]
    fn 空_matcher_匹配一切() {
        // Config 层保证至少定义一个条件，此处仅验证 matcher 自身语义
        let m = Matcher::new(None, None, None);
        assert!(m.matches(HEX40));
    }

    #[test]
    fn 空_needle_视为未定义() {
        let m = Matcher::new(Some(Vec::new()), None, None);
        assert!(m.matches(HEX40));
    }
}
