use config::{Config, File};
use std::io::{self, Write};

mod client;
mod mev;
mod settings;

use crate::client::SolanaClient;
use crate::mev::MevDetector;
use crate::settings::Settings;
use log::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .add_source(File::with_name("config"))
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
    let detector = MevDetector::new(settings.mev_detection.clone());

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

    info!("获取目标交易信息成功，区块: {}", target_tx.slot);

    // 步骤 1: 检查是否为简单转账
    if detector.is_simple_transfer(&target_tx) {
        println!("✅ 该交易为简单转账，不涉及Swap，无MEV风险。");
        return Ok(());
    }

    println!("🔍 该交易涉及Swap/DEX，开始MEV风险分析...");

    // 步骤 2: 获取目标交易周围的交易（前4笔和后4笔）
    let (nearby_transactions, target_index) =
        match client.get_nearby_transactions(target_signature).await {
            Ok(result) => result,
            Err(e) => {
                error!("获取周围交易信息失败: {}", e);
                println!("💡 修改config.toml中的rpc_url或许可以解决问题");
                return Err(e);
            }
        };

    println!(
        "📊 获取到周围{}笔交易，开始分析...",
        nearby_transactions.len()
    );

    // 步骤 3: 检查前后交易是否有Jito小费地址
    let jito_tip_info =
        detector.check_jito_tip_in_nearby_transactions(&nearby_transactions, target_index);

    match jito_tip_info {
        Some((tip_index, _tip_account, tip_amount, is_tip_before_target, bundle_transactions)) => {
            println!("🎯 检测到Jito捆绑包交易，正在分析MEV攻击...");

            let tip_position = if is_tip_before_target { "前" } else { "后" };
            println!("📍 Jito小费位置: 目标交易{}方", tip_position);
            println!(
                "💰 小费金额: {:.6} SOL",
                tip_amount as f64 / 1_000_000_000.0
            );

            // 显示捆绑包中的交易
            println!("📦 捆绑包包含{}笔交易:", bundle_transactions.len());
            for (i, tx) in bundle_transactions.iter().enumerate() {
                if tx.signature == nearby_transactions[tip_index].signature {
                    println!("  {}. Jito小费交易 ⭐", i + 1);
                } else if tx.signature == target_signature {
                    println!("  {}. 目标交易 🎯", i + 1);
                } else {
                    println!("  {}. 其他交易", i + 1);
                }
            }

            // MEV攻击检测和结果展示
            if let Some(sandwich) =
                detector.detect_sandwich_attack(&bundle_transactions, target_signature)
            {
                println!("\n🚨 检测到三明治攻击!");
                println!("  前置交易: https://solscan.io/tx/{}", sandwich.front_tx);
                println!("  后置交易: https://solscan.io/tx/{}", sandwich.back_tx);
                println!("  共享账户数: {}", sandwich.account_intersection.len());

                // 显示损失计算结果
                if let Some(loss) = &sandwich.user_loss {
                    println!("\n💸 用户损失估算:");
                    println!(
                        "  损失金额: {:.6} SOL",
                        loss.estimated_loss_lamports as f64 / 1_000_000_000.0
                    );
                    println!("  损失百分比: {:.2}%", loss.loss_percentage);
                    println!(
                        "  MEV利润: {:.6} SOL",
                        loss.mev_profit_lamports as f64 / 1_000_000_000.0
                    );
                    println!("  计算方法: {}", loss.calculation_method);
                } else {
                    println!("  ⚠️ 无法计算具体损失金额");
                }

                println!("  ℹ️ 已跳过抢跑检测（避免重复报告）");
            } else {
                // 只有在未检测到三明治攻击时才检测抢跑攻击
                if let Some(frontrun) =
                    detector.detect_frontrun_attack(&bundle_transactions, target_signature)
                {
                    println!("\n🚨 检测到抢跑攻击!");
                    println!("  抢跑交易: https://solscan.io/tx/{}", frontrun.front_tx);
                    println!("  共享账户数: {}", frontrun.account_intersection.len());
                } else {
                    println!("\n✅ 未检测到MEV攻击");
                }
            }

            println!("\n⚠️ 注意: 检测结果仅供参考，建议结合实际交易数据验证");
        }
        None => {
            println!("✅ 未发现Jito小费交易");
            println!("💡 这可能意味着:");
            println!("   • 确实没有被MEV攻击");
            println!("   • MEV攻击不是通过Jito捆绑包进行的");
        }
    }

    Ok(())
}
