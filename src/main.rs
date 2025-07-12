use config::Config;
use serde::Deserialize;
use std::io::{self, Write};

mod client;
mod mev;

use crate::client::SolanaClient;
use crate::mev::MevDetector;
use log::{error, info, warn};

#[derive(Debug, Deserialize)]
struct Settings {
    rpc_url: String,
    log_level: String,
    #[serde(default)]
    auto_detect_hashes: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .add_source(config::File::with_name("config"))
        .build()?;

    let settings: Settings = config.try_deserialize()?;

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&settings.log_level),
    )
    .format_timestamp_secs()
    .init();

    info!("Solana MEV 检测器启动...");
    println!("{}", "=".repeat(60));
    println!("🔍 Solana MEV 检测器 v0.2.0");
    println!("{}", "=".repeat(60));

    let client = SolanaClient::new(settings.rpc_url)?;
    let detector = MevDetector;

    // 检查是否有自动检测的哈希列表
    if !settings.auto_detect_hashes.is_empty() {
        println!(
            "\n🤖 检测到配置中有 {} 个预设的交易哈希，开始自动检测...",
            settings.auto_detect_hashes.len()
        );

        for (index, hash) in settings.auto_detect_hashes.iter().enumerate() {
            println!("\n{}", "=".repeat(80));
            println!(
                "🔄 自动检测 [{}/{}]: {}",
                index + 1,
                settings.auto_detect_hashes.len(),
                hash
            );
            println!("{}", "=".repeat(80));

            match analyze_transaction(&client, &detector, hash).await {
                Ok(_) => {
                    println!("✅ 自动检测完成！");
                }
                Err(e) => {
                    error!("❌ 自动检测失败: {}", e);
                }
            }
        }

        println!("\n{}", "=".repeat(80));
        println!("🎉 所有预设交易哈希检测完成！");
        println!("{}", "=".repeat(80));
    }

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

                if target_signature.eq_ignore_ascii_case("exit")
                    || target_signature.eq_ignore_ascii_case("quit")
                {
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

async fn analyze_transaction(
    client: &SolanaClient,
    detector: &MevDetector,
    target_signature: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let (nearby_transactions, target_index) =
        match client.get_nearby_transactions(target_signature).await {
            Ok(result) => result,
            Err(e) => {
                error!("获取周围交易信息失败: {}", e);
                info!("修改config.toml 中的rpc_url 或许可以解决问题");
                return Err(e);
            }
        };

    info!(
        "获取目标交易周围的 {} 笔交易成功，开始分析...",
        nearby_transactions.len()
    );

    // 步骤 3: 检查前后交易是否有Jito小费地址
    let jito_tip_info =
        detector.check_jito_tip_in_nearby_transactions(&nearby_transactions, target_index);

    match jito_tip_info {
        Some((tip_index, tip_account, tip_amount, is_tip_before_target, bundle_transactions)) => {
            info!("🔍 检测到临近交易存在Jito交易，可能被MEV，正在检测...");

            let tip_position = if is_tip_before_target {
                "前面"
            } else {
                "后面"
            };
            info!("📍 Jito小费交易位置: 在目标交易{}", tip_position);

            // 显示捆绑包中的交易哈希
            info!("📋 Jito捆绑包中的{}笔交易:", bundle_transactions.len());
            for (i, tx) in bundle_transactions.iter().enumerate() {
                if tx.signature == nearby_transactions[tip_index].signature {
                    warn!(
                        "  {}. https://solscan.io/tx/{} ⭐ (Jito小费交易)",
                        i + 1,
                        tx.signature
                    );
                } else if tx.signature == target_signature {
                    warn!(
                        "  {}. https://solscan.io/tx/{} 🎯 (目标交易)",
                        i + 1,
                        tx.signature
                    );
                } else {
                    info!("  {}. https://solscan.io/tx/{}", i + 1, tx.signature);
                }
            }

            info!(
                "  -> 小费金额: {} lamports ({:.9} SOL)",
                tip_amount,
                tip_amount as f64 / 1_000_000_000.0
            );

            // 在这个已确认的捆绑包内进行三明治和抢跑分析（包含Jito交易本身）
            if let Some(sandwich) =
                detector.detect_sandwich_attack(&bundle_transactions, target_signature)
            {
                error!("  🥪 检测到三明治攻击:");
                info!("    前置交易: https://solscan.io/tx/{}", sandwich.front_tx);
                info!("    后置交易: https://solscan.io/tx/{}", sandwich.back_tx);
                info!("    预估用户损失: {:.6} SOL", sandwich.victim_loss_estimate);
            } else {
                info!("  ✅ 未检测到三明治攻击");
            }

            if let Some(frontrun) =
                detector.detect_frontrun_attack(&bundle_transactions, target_signature)
            {
                error!("  🏃 检测到抢跑攻击:");
                info!("    抢跑交易: https://solscan.io/tx/{}", frontrun.front_tx);
            } else {
                info!("  ✅ 未检测到抢跑攻击");
            }

            warn!(" ⚠️ 解析不一定正确，如果临近交易有给jito的小费的交易，请根据日志信息再次确认");
        }
        None => {
            info!("✅ 在前4笔和后4笔交易中未发现Jito小费地址。");
            info!("💡 这可能意味着:");
            info!("   1. 确实没有被MEV攻击");
            info!("   2. MEV攻击不是通过Jito捆绑包进行的");
        }
    }

    Ok(())
}
