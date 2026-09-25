# 调研摘要 — vanity-generator（以太坊靓号地址生成器）

调研日期：2026-09-25。调研来源共 9 项，均为规格指定的清单。

## 一、权威项目实现（行为参照，非抄代码）

### 1. MetaMask/metamask-mobile + MetaMask/eth-hd-keyring（已读实际源码）
关键结论：
- 助记词生成：`bip39.generateMnemonic`（@metamask/scure-bip39，英文词表），
  熵来自平台 CSPRNG（操作系统安全随机，非应用层 PRNG）。
- 使用前先 `validateMnemonic`；种子 = `mnemonicToSeedSync(mnemonic, "")`（空 passphrase）。
- 派生：`HDKey.fromMasterSeed(seed)` → `m/44'/60'/0'/0` → `deriveChild(i)`，
  即 `m/44'/60'/0'/0/i`。
- 地址：`keccak256(未压缩公钥 64 字节)` 取后 20 字节，小写 hex 输出。

采纳：整条 熵→助记词→种子→BIP32→公钥→Keccak→地址 链路与其行为对齐；
默认路径 `m/44'/60'/0'/0/0`；英文词表；熵源强制 OsRng。

### 2. okxlabs/okx-smart-wallet-evm（已核查全仓 102 个文件）
关键结论：该仓库是 Solidity 智能合约项目（ERC-4337 SmartWallet、Passkey 验证器，
附 CertiK/BlockSec 审计报告），不含 BIP32/BIP39 密钥派生代码。
处理：派生流程与地址计算顺序的行为参照改以 MetaMask 实现 + BIP32/BIP39 规范为准，
不强行借鉴（如实说明，不做虚构引用）。

## 二、规范核对

### 3. bip39.dev/zh
- 熵必须来自强随机源；不要存储熵，存储助记词。
- 词数 12/15/18/21/24 ↔ 熵 128/160/192/224/256 位；末词是校验词，
  校验位宽 = 熵长/32（12 词→4 位，18 词→6 位，24 词→8 位）。

### 4. bip32.org
- 在线派生演示工具（JS，Alpha，代码陈旧）。仅取概念：hardened（'）与 normal
  派生、路径记法 `m/44'/60'/0'/0/i`。实现代码不参考（遵守安全红线）。

## 三、Rust 性能文档（优化候选唯一来源）

### 5. The Rust Performance Book（nnethercote）
- Build Configuration：`lto = "fat"`（10-20%+ 收益）、`codegen-units = 1`、
  `panic = "abort"`、strip symbols。
- Allocation：热路径避免堆分配、避免 String/Vec 反复分配、优先栈上缓冲。
- Bounds Checks：slice 相等比较编译为 memcmp，是最快的比较路径。

### 6. cargo Profile 官方文档
- 确认 `[profile.release]` 字段语义；release 默认 `codegen-units = 16`，须手动改 1。

### 7. rayon 官方文档（scope 章节）
- `rayon::scope` + `spawn` 可在循环中 spawn 任意数量任务，scope 结束前等待全部完成；
  scope 任务堆分配（vs join 栈上）。无限循环 worker + 停止标志正是 scope+spawn 场景。

### 8. memchr README（含官方基准）
- x86_64：SSE2 基线，std 启用时运行时检测自动升级 AVX2。
- `memmem::Finder` 预构建可摊销搜索器构造成本（oneshot 每次都要付费）；
  官方基准 memmem 比 `std` 的 contains 快约 5.3-6.5 倍。

### 9. tiny-keccak README
- 特性门控：必须开启 `keccak` feature 才能用 `Keccak::v256()`。

## 四、依赖精确锁定（已逐个查询 crates.io 索引，均写 `=x.y.z`）

| crate | 版本 | crate | 版本 |
|---|---|---|---|
| bip39 | =1.2.0 | rayon | =1.10.0 |
| rand | =0.9.5 | memchr | =2.7.6 |
| rand_core | =0.9.5 (getrandom) | crossbeam-channel | =0.5.17 |
| k256 | =0.13.4 (ecdsa,arithmetic) | serde | =1.0.229 (derive) |
| tiny-keccak | =2.0.2 (keccak) | serde_yaml | =0.9.34 |
| sequoia-openpgp | =1.21.2 | clap | =4.5.61 (derive) |
| anyhow | =1.0.104 | thiserror | =1.0.69 |
| zeroize | =1.8.2 (derive) | hex | =0.4.3 |
| criterion | =0.5.1 | （拟新增）bip32 | =0.5.3 |

## 五、性能模型预判（以 criterion 实测为准）

- 单次"生成-检查"成本 ≈ PBKDF2-HMAC-SHA512×2048 轮（BIP39 种子，占大头）
  + 2 次 secp256k1 点乘（`m/44'/60'/0'/0/0` 仅两级 normal 派生需要点乘，
  三级 hardened 无 EC 运算）+ Keccak×1。
- 匹配路径：front（memcmp 剪枝）→ back（memcmp）→ middle（memmem SIMD），
  命中后才算 EIP-55 校验和。
- 本机 sandbox 仅 2 核 x86_64：多线程扩展性验证以 2 线程为准，
  4/8 线程数据为超订阅参考，README 将注明硬件规格。

## 六、安全红线冲突点与决策请求（默认值可整体确认）

1. sequoia-openpgp 加密后端：默认 nettle 是 C 库（违背单二进制交付）。
   建议改用官方支持的 `crypto-rust` 后端（纯 Rust），输出格式与 GnuPG 兼容性不变。**默认：crypto-rust。**
2. 补充依赖 bip32 =0.5.3（rust-bitcoin 官方生态）：规格生成流程提到
   ExtendedPrivKey，但依赖清单未列。用它避免手写 BIP32 CKD 协议层；
   备选是基于 hmac+sha2+k256 手写协议层（原语仍是权威库）。**默认：引入 bip32 crate。**
3. rust-version：规格要求声明 1.75，但 sequoia-openpgp 1.21 的 MSRV 为 1.79，
   声明下限须 ≥1.79 才真实可编译（本机 rustc 1.98.1）。**默认：rust-version = "1.79"。**
4. criterion 特性：默认含 HTML 报告（构建慢）；建议 default-features=false +
   cargo_bench_support，仅输出基准数据。**默认：精简特性。**
5. （信息项）若基准显示 PBKDF2 占比 >70%，可评估 patch.crates-io 为 sha2 开
   asm 特性（RustCrypto 官方汇编）。不在指定文档清单内，默认不做。
