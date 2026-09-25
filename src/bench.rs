//! bench.rs —— criterion 基准共享样本与入口
//!
//! 当前（第 1 步）：匹配器核心基准样本；
//! 第 7-8 步补充：
//! a. 单线程每秒可测试地址数（全链路 熵→地址）；
//! b. 2 / 4 / 8 / N 线程吞吐（N = available_parallelism）；
//! c. front / back / middle 分解耗时（已就绪）；
//! d. 助记词生成到地址的全链路耗时。

/// 基准样本地址：40 字节小写 hex（前缀 8888、中段 a、后缀 8888）
pub const SAMPLE_HEX40: &[u8; 40] = b"8888aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8888";

/// 未命中样本：首字符即不满足 8888 前缀（最常见剪枝路径）
pub const SAMPLE_HEX40_MISS: &[u8; 40] = b"7888aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8888";
