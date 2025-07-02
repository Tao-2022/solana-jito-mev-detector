# Solana MEV 攻击检测器

一个轻量级的 Solana 链上交易分析工具，用于检测 **三明治攻击（Sandwich Attack）** 和 **抢跑攻击（Frontrun Attack）** 等最大可提取价值（MEV）行为。

## 功能特点

* 通过 Solana RPC 获取指定交易信息
* 自动抓取目标交易所在区块的周边交易
* 基于 DEX 合约地址和交易结构检测三明治攻击
* 基于时间差和程序相似度检测抢跑攻击

## 项目结构

```
src/
├── main.rs        # 主程序入口，交互逻辑
├── client.rs      # SolanaClient 实现：RPC 请求与交易解析
└── mev.rs         # MevDetector 实现：MEV 检测逻辑
```

## 运行要求

* Rust 环境（推荐 2021 edition）
* Solana 主网 RPC（推荐使用 [Helius](https://www.helius.xyz/) 提供的服务）

### Cargo 依赖（在 `Cargo.toml` 中添加）

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
reqwest = { version = "0.11", features = ["json", "gzip", "rustls-tls"] }
tokio = { version = "1", features = ["full"] }
```

## 使用方法

1. 克隆本仓库：

   ```bash
   git clone https://github.com/Tao-2022/solana-mev-detector-simple.git
   cd solana-mev-detector
   ```
2. 修改 `main.rs` 中的 RPC 地址：

   ```rust
   let rpc_url = "https://mainnet.helius-rpc.com/?api-key=你的API密钥".to_string();
   ```
3. 编译运行：

   ```bash
   cargo run --release
   ```
4. 根据提示输入目标交易哈希：

   ```text
   [INFO] 步骤1: 输入Solana交易哈希:
   > 请输入目标交易哈希
   ```

## 示例输出

```text
[INFO] 获取目标交易信息成功，所在区块: 215890000
[INFO] 获取 11 笔相关交易，开始分析...
[ALERT] 🚨 检测到三明治攻击:
  前置交易: https://solscan.io/tx/...
  后置交易: https://solscan.io/tx/...
  估算利润: 1.00%
[ALERT] 🚨 检测到抢跑攻击:
  抢跑交易: https://solscan.io/tx/...
  受害交易: https://solscan.io/tx/...
  时间差: 2000 毫秒
```

## 注意事项

* 当前利润估算为固定值（0.01），实际可结合 Swap Token 金额和 Pool 状态估算精度
* 检测逻辑以 DEX Program ID 识别为主（支持 Raydium、Orca、Serum）


