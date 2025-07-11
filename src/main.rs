use crossterm::event::{self, Event, KeyCode};
use crossterm::{terminal, execute};
use std::io::{stdout, Write};
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

    let client = SolanaClient::new(settings.rpc_url)?;
    let detector = MevDetector;

    terminal::enable_raw_mode()?;
    let mut stdout = stdout();

    loop {
        let mut target_signature = String::new();
        
        // 用户输入界面
        loop {
            execute!(stdout, terminal::Clear(terminal::ClearType::All))?;
            print!("请输入Solana交易哈希 (按 ESC 键退出):\n> {}", target_signature);
            stdout.flush()?;

            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char(c) => {
                        target_signature.push(c);
                    }
                    KeyCode::Backspace => {
                        target_signature.pop();
                    }
                    KeyCode::Enter => {
                        break;
                    }
                    KeyCode::Esc => {
                        terminal::disable_raw_mode()?;
                        println!("\n程序退出。");
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        terminal::disable_raw_mode()?;
        let target_signature = target_signature.trim();

        if target_signature.is_empty() {
            println!("[WARN] 未输入交易哈希，请重新输入。");
            terminal::enable_raw_mode()?;
            continue;
        }

        println!("\n正在分析交易: {}", target_signature);

        // 分析交易
        match analyze_transaction(&client, &detector, target_signature).await {
            Ok(_) => {
                println!("\n分析完成！");
            }
            Err(e) => {
                error!("分析失败: {}", e);
            }
        }

        // 等待用户按键继续
        println!("\n按任意键继续输入新的交易哈希，或按 ESC 键退出...");
        terminal::enable_raw_mode()?;
        if let Event::Key(key) = event::read()? {
            if key.code == KeyCode::Esc {
                terminal::disable_raw_mode()?;
                println!("\n程序退出。");
                return Ok(());
            }
        }
    }
}

async fn analyze_transaction(client: &SolanaClient, detector: &MevDetector, target_signature: &str) -> Result<(), Box<dyn std::error::Error>> {
    match client.get_transaction(target_signature).await {
        Ok(target_tx) => {
            info!("获取目标交易信息成功，所在区块: {}", target_tx.slot);

            // 步骤 1: 检查是否为简单转账
            if detector.is_simple_transfer(&target_tx) {
                info!("✅ 该交易为简单转账，不涉及Swap，不会被MEV。");
                return Ok(());
            }
            info!("该交易涉及Swap/DEX，继续分析MEV风险...");

            // 步骤 2: 获取整个区块的交易
            match client.get_full_block(target_tx.slot).await {
                Ok(block_transactions) => {
                    info!("获取区块 {} 的 {} 笔交易成功，开始分析...", target_tx.slot, block_transactions.len());

                    let target_index = block_transactions.iter().position(|tx| tx.signature == target_signature);

                    if let Some(index) = target_index {
                        // 步骤 3: 检查前3笔和后4笔交易是否有Jito小费地址
                        if detector.check_jito_tip_in_nearby_transactions(&block_transactions, index) {
                            info!("🔍 检测到临近交易存在Jito交易，可能被MEV，正在检测...");
                            
                            // 步骤 4: 寻找Jito捆绑包
                            if let Some(jito_bundle) = detector.find_jito_tip_and_bundle(&block_transactions, index) {
                                // 检查目标交易是否在捆绑包中
                                if jito_bundle.bundle_transactions.iter().any(|tx| tx.signature == target_signature) {
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

                                } else {
                                    info!("✅ 找到一个Jito捆绑包，但您的交易不在其中。初步判断没有被MEV。");
                                }
                            } else {
                                info!("✅ 临近交易虽然存在Jito地址，但未形成完整的捆绑包。初步判断没有被MEV。");
                            }
                        } else {
                            info!("✅ 在前3笔和后4笔交易中未发现Jito小费地址。没有被MEV。");
                        }
                    } else {
                        error!("在获取到的区块中未能定位到目标交易，可能由于RPC节点延迟。请稍后重试。");
                    }
                },
                Err(e) => error!("获取完整区块信息失败: {}", e),
            }
        }
        Err(e) => error!("获取目标交易失败: {}", e),
    }

    Ok(())
}