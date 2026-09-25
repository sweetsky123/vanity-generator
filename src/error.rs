//! error.rs —— 中英双语错误定义
//!
//! 所有 fatal error 的统一输出格式：
//! ```text
//! [ERROR / 错误]
//! EN: {英文信息，含上下文与修复建议}
//! CN: {中文信息，含上下文与修复建议}
//! ```
//!
//! 约定：
//! - 每条错误必须具体，禁止只写 "invalid config"；
//! - 每条错误必须带修复建议；
//! - 不允许 panic，一律 Result + anyhow 传播；
//! - 错误信息只引用字段名与当前非法取值，不回显整个配置文件内容。

use std::fmt;

/// 项目统一错误：每条错误同时携带英文与中文描述。
#[derive(Debug)]
pub struct VanityError {
    /// 错误类别标签（"config" / "io" / "internal" 等），仅用于定位
    pub kind: &'static str,
    /// 英文信息（含上下文与修复建议）
    pub en: String,
    /// 中文信息（含上下文与修复建议）
    pub cn: String,
}

impl VanityError {
    /// 配置类错误
    pub fn config(en: impl Into<String>, cn: impl Into<String>) -> Self {
        Self {
            kind: "config",
            en: en.into(),
            cn: cn.into(),
        }
    }

    /// IO 类错误（文件读写等）
    pub fn io(en: impl Into<String>, cn: impl Into<String>) -> Self {
        Self {
            kind: "io",
            en: en.into(),
            cn: cn.into(),
        }
    }

    /// 内部错误
    pub fn internal(en: impl Into<String>, cn: impl Into<String>) -> Self {
        Self {
            kind: "internal",
            en: en.into(),
            cn: cn.into(),
        }
    }

    /// 骨架阶段的占位错误：对应功能将在后续步骤实现
    pub fn not_implemented(feature: &str) -> Self {
        Self::internal(
            format!("{feature} is not implemented yet (skeleton build); it lands in a later step."),
            format!("{feature} 尚未实现（骨架版本），将在后续步骤落地。"),
        )
    }

    /// 按统一格式渲染错误文本
    pub fn render(&self) -> String {
        format!("[ERROR / 错误]\nEN: {}\nCN: {}", self.en, self.cn)
    }
}

impl fmt::Display for VanityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display 直接输出统一双语格式
        write!(f, "{}", self.render())
    }
}

impl std::error::Error for VanityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 双语格式渲染() {
        let e = VanityError::config("bad value. Fix it.", "非法取值。请修正。");
        let text = e.render();
        assert!(text.starts_with("[ERROR / 错误]\nEN: bad value. Fix it.\nCN: 非法取值。请修正。"));
        // Display 与 render 一致
        assert_eq!(text, format!("{e}"));
    }

    #[test]
    fn 转换为_std_error() {
        let e = VanityError::io("io failed", "IO 失败");
        let boxed: Box<dyn std::error::Error> = Box::new(e);
        assert!(boxed.to_string().contains("[ERROR / 错误]"));
    }
}
