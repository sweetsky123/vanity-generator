//! config.rs —— config.yaml 的解析与严格校验
//!
//! 校验规则（规格 config_schema 一节，全部为 fatal error）：
//! - `word_count` 只允许 12 / 18 / 24；
//! - `front` / `middle` / `back` 至少定义一个，取值只能含 [0-9a-fA-F]，
//!   可带 `0x` 前缀（解析时归一化），front 与 back 总长 ≤ 40；
//! - `path` 必须以 `m/` 开头，每层为合法 hardened（`'`/`h`/`H`）或 normal 索引；
//! - `count` 介于 1..=1000；
//! - `gpg_key_file` 必须可读且首行以 `-----BEGIN PGP PUBLIC KEY BLOCK-----` 开头
//!   （后缀名不做任何限制）；
//! - 任何字段类型错误同样是 fatal error。
//!
//! 错误信息只引用字段名与当前非法取值（规格示例风格），不回显整个文件。

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::VanityError;

/// 支持的助记词词数（BIP39：词数 ↔ 熵长）
pub const VALID_WORD_COUNTS: [u64; 3] = [12, 18, 24];

/// 默认 BIP32 派生路径（与 MetaMask 行为对齐）
pub const DEFAULT_PATH: &str = "m/44'/60'/0'/0/0";

/// GPG 公钥 ASCII armor 首行标记
const ARMOR_HEADER: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/// 地址 hex 长度（去掉 0x 后）
const ADDR_HEX_LEN: usize = 40;

/// front 与 back 的总长度上限
const FRONT_BACK_TOTAL_MAX: usize = 40;

/// count 取值范围
const COUNT_MIN: u64 = 1;
const COUNT_MAX: u64 = 1000;

/// BIP32 单层索引上限（2^31 - 1）
const BIP32_INDEX_MAX: u32 = 2_147_483_647;

/// serde 反序列化原始结构：字段类型即第一道校验
///（类型错误由 serde 直接报错，再映射为双语 fatal error）
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    word_count: u64,
    front: Option<String>,
    middle: Option<String>,
    back: Option<String>,
    path: Option<String>,
    count: u64,
    gpg_key_file: String,
}

/// 校验完成后的最终配置（所有靓号字段已归一化为小写 hex 字节）
#[derive(Debug, Clone)]
pub struct Config {
    /// 助记词词数：12 / 18 / 24
    pub word_count: u8,
    /// 前缀（小写 hex 字节，已去 0x；匹配用）
    pub front: Option<Vec<u8>>,
    /// 中缀（小写 hex 字节）
    pub middle: Option<Vec<u8>>,
    /// 后缀（小写 hex 字节，已去 0x；匹配用）
    pub back: Option<Vec<u8>>,
    /// 派生路径（用户原样写法，已验证合法性；输出明文时回显）
    pub path: String,
    /// 解析后的派生索引（hardened 位已置位，供派生器使用）
    pub path_indices: Vec<u32>,
    /// 目标命中数量
    pub count: u32,
    /// GPG 公钥文件（已相对 base_dir 解析为具体路径）
    pub gpg_key_file: PathBuf,
}

impl Config {
    /// 从指定路径加载并校验配置。
    /// `base_dir`：可执行文件所在目录，用于解析 `gpg_key_file` 相对路径。
    pub fn load(path: &Path, base_dir: &Path) -> Result<Self, VanityError> {
        let text = fs::read_to_string(path).map_err(|e| {
            VanityError::config(
                format!(
                    "failed to read config file {}: {e}. Please put config.yaml in the same \
                     directory as the executable and check file permissions.",
                    path.display()
                ),
                format!(
                    "读取配置文件 {} 失败：{e}。请确认 config.yaml 与可执行文件同目录且可读。",
                    path.display()
                ),
            )
        })?;
        Self::parse_and_validate(&text, base_dir)
    }

    /// 解析并校验 YAML 文本（加载与测试共用入口）
    pub fn parse_and_validate(text: &str, base_dir: &Path) -> Result<Self, VanityError> {
        // 1. 类型层校验：serde_yaml 错误统一映射为双语格式
        let raw: RawConfig = serde_yaml::from_str(text).map_err(|e| {
            VanityError::config(
                format!(
                    "failed to parse config.yaml: {e}. Please fix the YAML syntax and field \
                     types, then restart."
                ),
                format!("解析 config.yaml 失败：{e}。请修正 YAML 语法与字段类型后重新运行。"),
            )
        })?;

        // 2. word_count
        if !VALID_WORD_COUNTS.contains(&raw.word_count) {
            return Err(VanityError::config(
                format!(
                    "word_count must be one of [12, 18, 24], got \"{}\". Please edit \
                     config.yaml and restart.",
                    raw.word_count
                ),
                format!(
                    "word_count 只能为 [12, 18, 24] 其中之一，当前为 \"{}\"。请修改 \
                     config.yaml 后重新运行。",
                    raw.word_count
                ),
            ));
        }

        // 3. 靓号字段归一化（去 0x、校验 hex 字符、转小写）
        let front = raw.front.as_deref().map(|s| normalize_vanity("front", s)).transpose()?;
        let middle = raw
            .middle
            .as_deref()
            .map(|s| normalize_vanity("middle", s))
            .transpose()?;
        let back = raw.back.as_deref().map(|s| normalize_vanity("back", s)).transpose()?;

        if front.is_none() && middle.is_none() && back.is_none() {
            return Err(VanityError::config(
                "at least one of front/middle/back must be defined in config.yaml. Please add \
                 a vanity rule and restart.",
                "config.yaml 中 front/middle/back 至少需要定义一个。请添加靓号规则后重新运行。",
            ));
        }

        // 4. 前后缀总长度 ≤ 40（去掉 0x 后）
        let total = front.as_ref().map_or(0, Vec::len) + back.as_ref().map_or(0, Vec::len);
        if total > FRONT_BACK_TOTAL_MAX {
            return Err(VanityError::config(
                format!(
                    "total length of front + back must not exceed {FRONT_BACK_TOTAL_MAX} hex \
                     chars, got {total}. Please shorten the prefix/suffix."
                ),
                format!(
                    "front 与 back 的总长度不能超过 {FRONT_BACK_TOTAL_MAX} 个 hex 字符，当前为 \
                     {total}。请缩短前后缀。"
                ),
            ));
        }

        // 5. middle 兜底：超过地址长度必然永远无法命中
        if middle.as_ref().is_some_and(|m| m.len() > ADDR_HEX_LEN) {
            return Err(VanityError::config(
                format!(
                    "middle must not exceed {ADDR_HEX_LEN} hex chars; a longer substring can \
                     never match an address. Please shorten it."
                ),
                format!(
                    "middle 不能超过 {ADDR_HEX_LEN} 个 hex 字符，超长子串永远无法命中地址。请缩短。"
                ),
            ));
        }

        // 6. path：必须以 m/ 开头，逐层校验
        let path = raw.path.as_deref().unwrap_or(DEFAULT_PATH).trim().to_string();
        let path_indices = parse_path(&path)?;

        // 7. count
        if !(COUNT_MIN..=COUNT_MAX).contains(&raw.count) {
            return Err(VanityError::config(
                format!(
                    "count must be between {COUNT_MIN} and {COUNT_MAX}, got \"{}\". Please edit \
                     config.yaml and restart.",
                    raw.count
                ),
                format!(
                    "count 必须介于 {COUNT_MIN} 到 {COUNT_MAX} 之间，当前为 \"{}\"。请修改 \
                     config.yaml 后重新运行。",
                    raw.count
                ),
            ));
        }

        // 8. gpg_key_file：可读 + armor 首行校验（相对 base_dir 解析）
        let gpg_path = resolve_path(base_dir, &raw.gpg_key_file);
        validate_gpg_armor(&gpg_path, &raw.gpg_key_file)?;

        Ok(Self {
            word_count: raw.word_count as u8,
            front,
            middle,
            back,
            path,
            path_indices,
            count: raw.count as u32,
            gpg_key_file: gpg_path,
        })
    }
}

/// 归一化靓号字段：去 0x 前缀、校验 hex 字符、转小写字节
fn normalize_vanity(field: &'static str, raw: &str) -> Result<Vec<u8>, VanityError> {
    let s = raw.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.is_empty() {
        return Err(VanityError::config(
            format!(
                "{field} must not be empty. Remove the field if it should not constrain \
                 matching."
            ),
            format!("{field} 不能为空。若不希望该字段参与匹配，请直接删除该字段。"),
        ));
    }
    if let Some(c) = s.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(VanityError::config(
            format!(
                "{field} may only contain hex characters [0-9a-fA-F], found '{c}'. Please fix \
                 config.yaml and restart."
            ),
            format!(
                "{field} 只能包含 [0-9a-fA-F] 十六进制字符，发现非法字符 '{c}'。请修改 \
                 config.yaml 后重新运行。"
            ),
        ));
    }
    Ok(s.to_ascii_lowercase().into_bytes())
}

/// 解析 BIP32 派生路径，返回逐层索引（hardened 已置高位）。
/// 合法形式：`m/` 前缀 + 若干层 `数字` 或 `数字'`/`数字h`/`数字H`。
/// `m/`（仅主密钥，零层派生）视为合法。
fn parse_path(path: &str) -> Result<Vec<u32>, VanityError> {
    if !path.starts_with("m/") {
        return Err(VanityError::config(
            "path must start with \"m/\". Please use a standard form such as \
             \"m/44'/60'/0'/0/0\".",
            "path 必须以 \"m/\" 开头。请使用如 \"m/44'/60'/0'/0/0\" 的标准写法。",
        ));
    }
    let rest = &path["m/".len()..];
    if rest.is_empty() {
        // 仅主密钥：seed 直接派生 XPrv，零层派生（合法边界）
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(8);
    for seg in rest.split('/') {
        if seg.is_empty() {
            return Err(VanityError::config(
                "path contains an empty segment (\"//\"). Please check each level, e.g. \
                 \"m/44'/60'/0'/0/0\".",
                "path 中存在空层级（\"//\"）。请检查每一层写法，例如 \"m/44'/60'/0'/0/0\"。",
            ));
        }
        // hardened 标记：' / h / H
        let (num_str, hardened) = match seg.as_bytes()[seg.len() - 1] {
            b'\'' | b'h' | b'H' => (&seg[..seg.len() - 1], true),
            _ => (seg, false),
        };
        if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(VanityError::config(
                format!(
                    "path segment \"{seg}\" is not a valid child index. Use digits with an \
                     optional ' / h / H suffix, e.g. 44' or 0."
                ),
                format!(
                    "path 层级 \"{seg}\" 不是合法的子索引。应为纯数字并可带 ' / h / H \
                     后缀，如 44' 或 0。"
                ),
            ));
        }
        let num: u64 = num_str.parse().map_err(|_| {
            VanityError::config(
                format!(
                    "path index \"{num_str}\" is too large to parse. Please lower the index \
                     value."
                ),
                format!("path 索引 \"{num_str}\" 数值过大无法解析。请调小索引值。"),
            )
        })?;
        if num > BIP32_INDEX_MAX as u64 {
            return Err(VanityError::config(
                format!(
                    "path index {num} exceeds the BIP32 limit {BIP32_INDEX_MAX}. Please lower \
                     the index."
                ),
                format!("path 索引 {num} 超出 BIP32 上限 {BIP32_INDEX_MAX}。请调小索引值。"),
            ));
        }
        out.push(num as u32 | (u32::from(hardened) * 0x8000_0000));
    }
    Ok(out)
}

/// 解析 gpg_key_file：绝对路径原样，相对路径基于 base_dir
fn resolve_path(base: &Path, name: &str) -> PathBuf {
    let p = Path::new(name);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// 校验公钥文件：可读 + 首行为 ASCII armor 公钥头
fn validate_gpg_armor(path: &Path, declared: &str) -> Result<(), VanityError> {
    let content = fs::read_to_string(path).map_err(|_| {
        VanityError::config(
            format!(
                "cannot read gpg_key_file \"{declared}\" (looked at {}). Please put the public \
                 key file next to the executable and check the filename.",
                path.display()
            ),
            format!(
                "无法读取 gpg_key_file \"{declared}\"（查找路径 {}）。请将公钥文件放在可执行文件 \
                 同目录并核对文件名。",
                path.display()
            ),
        )
    })?;
    // 首行：容忍 BOM 与前后空白（规格：首行以 armor 头开头即可）
    let first_line = content
        .lines()
        .next()
        .unwrap_or("")
        .trim_start_matches('\u{feff}')
        .trim();
    if !first_line.starts_with(ARMOR_HEADER) {
        return Err(VanityError::config(
            format!(
                "the first line of gpg_key_file \"{declared}\" must start with \
                 \"{ARMOR_HEADER}\". Make sure it is an ASCII-armored OpenPGP public key \
                 (any file extension is fine)."
            ),
            format!(
                "gpg_key_file \"{declared}\" 的首行必须以 \"{ARMOR_HEADER}\" 开头。请确认该文件是 \
                 ASCII armor 格式的 OpenPGP 公钥（后缀名不限）。"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试基目录：仓库根（用于解析 tests/fixtures/fx1024.asc）
    fn base() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn key_yaml() -> String {
        String::from(
            "word_count: 24\nfront: \"0x8888\"\nback: \"8888\"\npath: \"m/44'/60'/0'/0/0\"\n\
             count: 5\ngpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        )
    }

    /// 替换 yaml 中的某个字段值，快速构造非法样例
    fn yaml_with(field: &str, value: &str) -> String {
        let mut yaml = key_yaml();
        if field == "path" {
            // 默认样例里有 path 行，整行替换
            let lines: Vec<String> = yaml
                .lines()
                .map(|l| {
                    if l.starts_with("path:") {
                        format!("path: {value}")
                    } else {
                        l.to_string()
                    }
                })
                .collect();
            yaml = lines.join("\n") + "\n";
        } else {
            yaml.push_str(&format!("{field}: {value}\n"));
        }
        yaml
    }

    #[test]
    fn 合法配置_完整样例() {
        let cfg = Config::parse_and_validate(&key_yaml(), &base()).unwrap();
        assert_eq!(cfg.word_count, 24);
        assert_eq!(cfg.front.as_deref(), Some(&b"8888"[..]));
        assert_eq!(cfg.back.as_deref(), Some(&b"8888"[..]));
        assert!(cfg.middle.is_none());
        assert_eq!(cfg.path, "m/44'/60'/0'/0/0");
        assert_eq!(
            cfg.path_indices,
            vec![0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 0]
        );
        assert_eq!(cfg.count, 5);
        assert!(cfg.gpg_key_file.ends_with("tests/fixtures/fx1024.asc"));
    }

    #[test]
    fn 合法配置_12_18_24_词数全路径() {
        for wc in [12u64, 18, 24] {
            let yaml = format!(
                "word_count: {wc}\nfront: \"ab\"\ncount: 1\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            );
            let cfg = Config::parse_and_validate(&yaml, &base()).unwrap();
            assert_eq!(cfg.word_count as u64, wc);
        }
    }

    #[test]
    fn word_count_非法_13() {
        let yaml = String::from(
            "word_count: 13\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("word_count must be one of [12, 18, 24], got \"13\""));
        assert!(err.cn.contains("当前为 \"13\""));
        assert!(err.en.contains("Please edit config.yaml"));
    }

    #[test]
    fn word_count_类型错误_字符串() {
        let yaml = String::from(
            "word_count: \"24\"\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("failed to parse config.yaml"));
        assert!(err.cn.contains("解析 config.yaml 失败"));
    }

    #[test]
    fn front_非法字符_0xgggg() {
        let yaml = String::from(
            "word_count: 12\nfront: \"0xGGGG\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("front may only contain hex characters"));
        assert!(err.cn.contains("发现非法字符"));
    }

    #[test]
    fn front_为空字符串() {
        let yaml = String::from(
            "word_count: 12\nfront: \"\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("front must not be empty"));
    }

    #[test]
    fn 靓号字段_全部缺失() {
        let yaml = String::from(
            "word_count: 12\ncount: 1\ngpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("at least one of front/middle/back"));
        assert!(err.cn.contains("至少需要定义一个"));
    }

    #[test]
    fn 前后缀总长超限_41() {
        let yaml = format!(
            "word_count: 12\nfront: \"{}\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n",
            "a".repeat(41)
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("total length of front + back must not exceed 40"));
        assert!(err.cn.contains("不能超过 40"));
    }

    #[test]
    fn 前后缀总长边界_40_正好合法() {
        let yaml = format!(
            "word_count: 12\nfront: \"{}\"\nback: \"{}\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n",
            "a".repeat(28),
            "b".repeat(12)
        );
        let cfg = Config::parse_and_validate(&yaml, &base()).unwrap();
        assert_eq!(cfg.front.as_ref().unwrap().len(), 28);
        assert_eq!(cfg.back.as_ref().unwrap().len(), 12);
    }

    #[test]
    fn middle_超长_41_必然无法命中() {
        let yaml = format!(
            "word_count: 12\nmiddle: \"{}\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n",
            "c".repeat(41)
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("middle must not exceed 40"));
    }

    #[test]
    fn path_空层级() {
        let err = Config::parse_and_validate(&yaml_with("path", "\"m//44'\""), &base()).unwrap_err();
        assert!(err.en.contains("empty segment"));
        assert!(err.cn.contains("空层级"));
    }

    #[test]
    fn path_缺少_m_前缀() {
        let err =
            Config::parse_and_validate(&yaml_with("path", "\"44'/60'\""), &base()).unwrap_err();
        assert!(err.en.contains("path must start with \"m/\""));
    }

    #[test]
    fn path_非法字符() {
        let err =
            Config::parse_and_validate(&yaml_with("path", "\"m/4x'/60'\""), &base()).unwrap_err();
        assert!(err.en.contains("is not a valid child index"));
    }

    #[test]
    fn path_索引超上限() {
        let err = Config::parse_and_validate(
            &yaml_with("path", "\"m/2147483648\""),
            &base(),
        )
        .unwrap_err();
        assert!(err.en.contains("exceeds the BIP32 limit 2147483647"));
    }

    #[test]
    fn path_极深_2147483647_合法() {
        let cfg = Config::parse_and_validate(
            &yaml_with("path", "\"m/44'/60'/0'/0/2147483647\""),
            &base(),
        )
        .unwrap();
        assert_eq!(*cfg.path_indices.last().unwrap(), 2_147_483_647);
    }

    #[test]
    fn path_仅主密钥_合法边界() {
        let cfg = Config::parse_and_validate(&yaml_with("path", "\"m/\""), &base()).unwrap();
        assert!(cfg.path_indices.is_empty());
    }

    #[test]
    fn path_h_大小写_hardened_等价() {
        let cfg = Config::parse_and_validate(&yaml_with("path", "\"m/44h/60H\""), &base()).unwrap();
        assert_eq!(cfg.path_indices, vec![0x8000_002C, 0x8000_003C]);
    }

    #[test]
    fn path_缺省_默认路径生效() {
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let cfg = Config::parse_and_validate(&yaml, &base()).unwrap();
        assert_eq!(cfg.path, DEFAULT_PATH);
        assert_eq!(cfg.path_indices.len(), 5);
    }

    #[test]
    fn count_越界_0_与_1001() {
        for bad in [0u64, 1001] {
            let yaml = format!(
                "word_count: 12\nfront: \"ab\"\ncount: {bad}\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            );
            let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
            assert!(err.en.contains("count must be between 1 and 1000"));
        }
    }

    #[test]
    fn count_边界_1_与_1000_合法() {
        for good in [1u64, 1000] {
            let yaml = format!(
                "word_count: 12\nfront: \"ab\"\ncount: {good}\n\
                 gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
            );
            let cfg = Config::parse_and_validate(&yaml, &base()).unwrap();
            assert_eq!(cfg.count as u64, good);
        }
    }

    #[test]
    fn gpg_文件不存在() {
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\ncount: 1\n\
             gpg_key_file: \"definitely_missing_key.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("cannot read gpg_key_file \"definitely_missing_key.asc\""));
        assert!(err.cn.contains("无法读取 gpg_key_file"));
    }

    #[test]
    fn gpg_首行不是_armor_头() {
        let bad = std::env::temp_dir().join(format!("vanity_bad_key_{}.txt", std::process::id()));
        std::fs::write(&bad, "hello not a pgp key\nsecond line\n").unwrap();
        let yaml = format!(
            "word_count: 12\nfront: \"ab\"\ncount: 1\ngpg_key_file: \"{}\"\n",
            bad.display()
        );
        let err = Config::parse_and_validate(&yaml, Path::new("/")).unwrap_err();
        assert!(err.en.contains("must start with \"-----BEGIN PGP PUBLIC KEY BLOCK-----\""));
        assert!(err.cn.contains("首行必须"));
    }

    #[test]
    fn gpg_任意后缀的纯文本公钥_合法() {
        // 后缀 .txt、.none 均可：只要能读且首行是 armor 头
        let key = std::fs::read_to_string(base().join("tests/fixtures/fx1024.asc")).unwrap();
        let txt = std::env::temp_dir().join(format!("vanity_txt_key_{}.txt", std::process::id()));
        std::fs::write(&txt, &key).unwrap();
        let noext =
            std::env::temp_dir().join(format!("vanity_noext_key_{}", std::process::id()));
        std::fs::write(&noext, &key).unwrap();
        for f in [txt, noext] {
            let yaml = format!(
                "word_count: 12\nfront: \"ab\"\ncount: 1\ngpg_key_file: \"{}\"\n",
                f.display()
            );
            let cfg = Config::parse_and_validate(&yaml, Path::new("/")).unwrap();
            assert_eq!(cfg.gpg_key_file, f);
        }
    }

    #[test]
    fn 未知字段_报错() {
        let yaml = String::from(
            "word_count: 12\nfront: \"ab\"\ncount: 1\nunknown_field: 1\n\
             gpg_key_file: \"tests/fixtures/fx1024.asc\"\n"
        );
        let err = Config::parse_and_validate(&yaml, &base()).unwrap_err();
        assert!(err.en.contains("failed to parse config.yaml"));
    }

    #[test]
    fn 必填字段缺失() {
        for missing in ["word_count", "count", "gpg_key_file"] {
            let yaml = key_yaml()
                .lines()
                .filter(|l| !l.starts_with(missing))
                .collect::<Vec<_>>()
                .join("\n");
            let err = Config::parse_and_validate(&format!("{yaml}\n"), &base()).unwrap_err();
            assert!(err.en.contains("failed to parse config.yaml"));
        }
    }
}
