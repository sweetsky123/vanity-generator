# 性能剖析与优化记录

本文记录一次完整的、以测量为依据的性能调查（对应规格 performance_optimization 的
迭代流程），所有数据来自本仓库自带工具，可复现。

## 测量工具

- `examples/perf_probe.rs`：与正式二进制相同 release profile（fat LTO、
  codegen-units=1）下的分阶段计时探针；
- `cargo bench`（criterion）：匹配器、PBKDF2、BIP32 派生、多线程吞吐；
- 正式二进制 12 秒真实运行（progress_every 读速率）。

## 瓶颈定位（数据）

单次"生成-检查"在 Intel Xeon 单核上的分解（24 词助记词）：

| 阶段 | 耗时 | 占比 |
|---|---|---|
| 熵 → 助记词（bip39 from_entropy_in） | ≈ 0.03 ms | 1% |
| **助记词 → 种子（PBKDF2-HMAC-SHA512 × 2048 轮）** | **≈ 1.77 ms** | **77%** |
| BIP32 派生 m/44'/60'/0'/0/0（3×hardened + 2×normal CKD） | ≈ 0.40 ms | 17% |
| 公钥点乘 + Keccak + hex + 匹配 | ≈ 0.15 ms | 5% |
| 合计 | ≈ 2.3 ms | 100% |

结论：BIP39 标准规定的 2048 轮 PBKDF2 是绝对主项（约 3/4），这是
"生成完整助记词"这一产品形态的固有成本，无法在标准内消除。

## 优化候选与 A/B 结果（按规格"不足 2% 即回滚"规则执行）

| 候选 | 来源 | A/B 结果 | 决定 |
|---|---|---|---|
| lto=fat + codegen-units=1 + panic=abort | Rust Performance Book《Build Configuration》 | 已在 release profile 生效（与规格一致） | 保留 |
| 栈上 [u8;40] hex 缓冲、命中才算 EIP-55 | Performance Book《Allocation》 | 匹配器单次 front 剪枝 ≈ 15ns，无堆分配 | 保留 |
| memmem Finder 预构建（SIMD） | memchr README | middle 搜索 ~5-6 倍于 std contains | 保留 |
| k256 precomputed-tables | k256 Cargo.toml | 默认已启用（点乘已最优） | 无需动作 |
| sha2 `asm` 特性（AVX2 汇编） | RustCrypto hashes 官方 | 本机 A/B：PBKDF2 1.764ms → 1.769ms（0%）；HMAC-PBKDF2 每轮仅处理单个 64B 块，AVX2 双块并行路径无法生效 | **回滚**（纯 Rust 构建，免 C 工具链，兼容性最大） |
| rayon 全局池 scope（修复 worker 槽位） | rayon 文档 scope 章节 | 自建 ThreadPool + install 会把 scope 闭包放进池内线程，占用一个 worker 槽位（实际并行度 N-1）；改为全局池 scope 后闭包在调用线程、N 个 worker 全部进池 | **修复**（真多核机器上恢复全部核心） |

## 并行扩展性说明

- 本开发沙箱实测：2 vCPU 实际仅提供约 1 个物理核的等效算力
  （双进程并发各自 220/s，合计与单进程一致），因此本机无法展示多线程扩展。
- 多线程扩展性门禁（吞吐 ≥ 单线程 × 0.7 × 线程数）在 GitHub Actions
  runner（真实多核）上执行，见 CI 的扩展性测试步骤。
- 真实多核机器上的预期：吞吐 ≈ 单核速率 × 核数 × 0.85 以上。

## 与浏览器靓号工具的对比说明

网页/手机浏览器里的靓号工具（如 Vanity-ETH 类）每次尝试只做
"随机私钥 → secp256k1 公钥 → Keccak → 地址"，没有 2048 轮 PBKDF2 的
BIP39 种子派生、没有 BIP32 链、没有 GPG 加密输出。两者单次成本相差约
两个数量级，直接对比 addr/s 并不公平。本工具的每一分成本都来自
"BIP39/BIP32 标准合规"与"助记词可直接导入任意钱包"这两项产品要求。

## 可选的进一步提速（会改变语义，默认未启用）

若接受"一个助记词派生多个地址（BIP44 标准行为，任何 HD 钱包都如此）"，
可对每个助记词扫描 m/44'/60'/0'/0/{i..i+k}：额外地址只需一次 CKD
（约 0.2ms）而非完整 2.3ms，吞吐可再提升约 10 倍。该模式与规格的
"每次尝试全新助记词"语义不同，如需要可作为配置项加入。
