use std::io::{self, Write};
use config::Config;
use serde::Deserialize;

mod client;
mod mev;

use crate::client::SolanaClient;
use crate::mev::MevDetector;
use log::{error, info};

#[derive(Debug, Deserialize)]
struct Settings {
    rpc_url: String,
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .add_source(config::File::with_name("config"))
        .build()?;

    let settings: Settings = config.try_deserialize()?;

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&settings.log_level))
        .format_timestamp_secs()
        .init();

    info!("Solana MEV 检测器启动...");
    println!("{}", "=".repeat(60));
    println!("🔍 Solana MEV 检测器 v0.2.0");
    println!("{}", "=".repeat(60));

    let client = SolanaClient::new(settings.rpc_url)?;
    let detector = MevDetector;

    loop {
        println!("\n请输入Solana交易哈希 (输入 'exit' 或 'quit' 退出):");
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let target_signature = input.trim();
                
                // 检查退出命令
                if target_signature.is_empty() {
                    continue;
                }
                
                if target_signature.eq_ignore_ascii_case("exit") || 
                   target_signature.eq_ignore_ascii_case("quit") {
                    println!("\n👋 程序退出，感谢使用！");
                    break;
                }

                println!("\n🔄 正在分析交易: {}", target_signature);
                println!("{}", "-".repeat(50));

                // 分析交易
                match analyze_transaction(&client, &detector, target_signature).await {
                    Ok(_) => {
                        println!("{}", "-".repeat(50));
                        println!("✅ 分析完成！");
                    }
                    Err(e) => {
                        println!("{}", "-".repeat(50));
                        error!("❌ 分析失败: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("读取输入失败: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn analyze_transaction(client: &SolanaClient, detector: &MevDetector, target_signature: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 获取目标交易
    let target_tx = match client.get_transaction(target_signature).await {
        Ok(tx) => tx,
        Err(e) => {
            error!("获取目标交易失败: {}", e);
            return Err(e);
        }
    };

    info!("获取目标交易信息成功，所在区块: {}", target_tx.slot);

    // 步骤 1: 检查是否为简单转账
    if detector.is_simple_transfer(&target_tx) {
        info!("✅ 该交易为简单转账，不涉及Swap，不会被MEV。");
        return Ok(());
    }
    
    info!("该交易涉及Swap/DEX，继续分析MEV风险...");

    // 步骤 2: 获取目标交易周围的交易（前4笔和后4笔）
    let (nearby_transactions, target_index) = match client.get_nearby_transactions(target_signature).await {
        Ok(result) => result,
        Err(e) => {
            error!("获取周围交易信息失败: {}", e);
            info!("修改config.toml 中的rpc_url 或许可以解决问题");
            return Err(e);
        }
    };

    info!("获取目标交易周围的 {} 笔交易成功，开始分析...", nearby_transactions.len());

    // 步骤 3: 检查前后非投票交易是否有Jito小费地址
    let jito_tip_info = detector.check_jito_tip_in_nearby_transactions(&nearby_transactions, target_index);
    
    match jito_tip_info {
        Some((tip_index, tip_account, tip_amount, nearby_hashes)) => {
            info!("🔍 检测到临近交易存在Jito交易，可能被MEV，正在检测...");
            
            // 显示前后非投票交易的哈希
            info!("📋 目标交易前后的{}笔非投票交易:", nearby_hashes.len());
            for (i, hash) in nearby_hashes.iter().enumerate() {
                if hash == &nearby_transactions[tip_index].signature {
                    info!("  {}. https://solscan.io/tx/{} ⭐ (Jito小费交易)", i + 1, hash);
                } else {
                    info!("  {}. https://solscan.io/tx/{}", i + 1, hash);
                }
            }
            
            // 步骤 4: 构建Jito捆绑包
            let jito_bundle = detector.build_jito_bundle(&nearby_transactions, tip_index, tip_account, tip_amount);

            error!("🚨 检测到Jito捆绑包! Jito捆绑包最多包含5笔交易，您的交易是其中之一。");
            info!("  -> 小费交易: https://solscan.io/tx/{}", jito_bundle.tip_tx_signature);
            info!("  -> 小费地址: {}", jito_bundle.tip_account);
            info!(
                "  -> 小费金额: {} lamports ({:.9} SOL)",
                jito_bundle.tip_amount_lamports,
                jito_bundle.tip_amount_lamports as f64 / 1_000_000_000.0
            );
            
            // 在这个已确认的捆绑包内进行三明治和抢跑分析
            let bundle_with_tip = [jito_bundle.bundle_transactions.as_slice(), &[target_tx.clone()]].concat();
            
            if let Some(sandwich) = detector.detect_sandwich_attack(&bundle_with_tip, target_signature) {
                error!("  🥪 在Jito捆绑包内检测到三明治攻击:");
                info!("    前置交易: https://solscan.io/tx/{}", sandwich.front_tx);
                info!("    后置交易: https://solscan.io/tx/{}", sandwich.back_tx);
                info!("    预估用户损失: {:.6} SOL", sandwich.victim_loss_estimate);
            } else {
                info!("  ✅ 在Jito捆绑包内未检测到三明治攻击");
            }

            if let Some(frontrun) = detector.detect_frontrun_attack(&bundle_with_tip, target_signature) {
                error!("  🏃 在Jito捆绑包内检测到抢跑攻击:");
                info!("    抢跑交易: https://solscan.io/tx/{}", frontrun.front_tx);
            } else {
                info!("  ✅ 在Jito捆绑包内未检测到抢跑攻击");
            }
        }
        None => {
            info!("✅ 在前4笔和后4笔非投票交易中未发现Jito小费地址。");
            info!("💡 这可能意味着:");
            info!("   1. 确实没有被MEV攻击");
            info!("   2. MEV攻击不是通过Jito捆绑包进行的");
        }
    }

    Ok(())
}