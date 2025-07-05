mod client;
mod mev;

use crate::client::SolanaClient;
use crate::mev::MevDetector;
use log::{error, info};
use std::io::{self, Write};


#[tokio::main]
/// 主函数，程序的入口点。
/// 初始化日志，获取用户输入的交易哈希，然后检测三明治攻击和抢跑攻击。
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    env_logger::Builder::from_default_env()
        .format_timestamp_secs()
        .init();

    info!("Solana MEV 检测器启动...");

    let rpc_url = "https://api.mainnet-beta.solana.com".to_string();
    let client = SolanaClient::new(rpc_url)?;
    let detector = MevDetector;

    info!(" 输入Solana交易哈希:");
    print!("> ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let target_signature = input.trim();

    if target_signature.is_empty() {
        println!("[WARN] 未输入交易哈希，程序退出。");
        return Ok(());
    }

    info!("正在分析交易: {}", target_signature);

    match client.get_transaction(target_signature).await {
        Ok(target_tx) => {
            info!("获取目标交易信息成功，所在区块: {}", target_tx.slot);

            match client
                .get_surrounding_transactions(target_signature, target_tx.slot)
                .await
            {
                Ok(surrounding_txs) => {
                    info!("获取 {} 笔相关交易，开始分析...", surrounding_txs.len());

                    if let Some(sandwich) =
                        detector.detect_sandwich_attack(&surrounding_txs, target_signature)
                    {
                        error!("🚨 检测到三明治攻击:");
                        info!("  前置交易: https://solscan.io/tx/{}", sandwich.front_tx);
                        info!("  后置交易: https://solscan.io/tx/{}", sandwich.back_tx);
                        info!("  估算利润: {:.2}%", sandwich.profit_estimate * 100.0);
                    } else {
                        info!("✅ 未检测到三明治攻击");
                    }

                    if let Some(frontrun) =
                        detector.detect_frontrun_attack(&surrounding_txs, target_signature)
                    {
                        error!("🚨 检测到抢跑攻击:");
                        info!("  抢跑交易: https://solscan.io/tx/{}", frontrun.front_tx);
                        info!("  受害交易: https://solscan.io/tx/{}", frontrun.victim_tx);
                    } else {
                        info!("✅ 未检测到抢跑攻击");
                    }
                }
                Err(e) => error!("获取周围交易失败: {}", e),
            }
        }
        Err(e) => error!("获取目标交易失败: {}", e),
    }

    Ok(())
}
