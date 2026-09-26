# Wiki 首页内容（供网页端初始化后粘贴）

> GitHub 的 Wiki 仓库必须先在网页上创建一次首页才能用 git 管理：
> 仓库页 → Wiki 标签页 → 点 "Create the first page" → 保存任意内容后，
> 即可把本文件内容粘贴/提交进去。

---

# vanity-generator Wiki

以太坊靓号地址生成器：BIP39 助记词 → BIP32 派生 → EIP-55 地址匹配 → GPG 加密落盘。

## 快速开始

1. 从 [Releases](https://github.com/sweetsky123/vanity-generator/releases) 下载对应平台包（Linux x64/ARM64、Windows x64、macOS x64/ARM64）
2. 解压后把 `config.example.yaml` 复制为 `config.yaml`，改好规则，与二进制同目录
3. `./vanity-generator --check` 预估难度 → 确认可接受后去掉 `--check` 正式运行
4. 命中产物 `vanity_*.asc` 用 `gpg --decrypt vanity_xxx.asc > wallet.txt` 解密

## 难度速查（单机约 450 次/秒，多核近线性）

| 规则 | 期望尝试 | 单机耗时 |
|---|---|---|
| 2 位前缀 | 256 | 秒级 |
| 4 位前缀 | 6.5 万 | 分钟级 |
| 5 位前缀 | 100 万 | 小时级 |
| 6 位前缀 | 1670 万 | 天级 |

每多一位 ×16；大小写敏感的字母位再 ×2；前后缀联合相乘。

## 多机并行演示

Actions → 靓号演示（多机并行）→ Run workflow，可选机器数（1-20，默认 8）。
需要两个仓库 Secret：`config`（config.yaml 内容）与 `gpg`（公钥 armor 内容）。

## 文档索引

- [性能剖析与优化记录](../blob/main/docs/performance.md)：为什么是 450/s（PBKDF2 占 77%）、
  rayon 槽位修复、sha2-asm A/B（0% 已回滚）、与浏览器靓号工具的对比说明
- README：完整配置项、安全模型、常见问题排错

## 安全红线

- 熵源只有系统 CSPRNG（OsRng/getrandom），无任何用户态熵参与
- 输出 GPG 加密，私钥不落明文；全程离线
- 全依赖树纯 Rust、`#![forbid(unsafe_code)]`
