use config::{Config, File};
use std::io::{self, Write};

mod client;
mod locale;
mod mev;
mod settings;

use crate::client::SolanaClient;
use crate::locale::Locale;
use crate::mev::MevDetector;
use crate::settings::Settings;
use log::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .add_source(File::with_name("config"))
        .build()?;

    let settings: Settings = config.try_deserialize()?;
    let locale = Locale::new(settings.language.clone());

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&settings.log_level),
    )
    .format_timestamp_secs()
    .init();

    info!("{}", locale.starting());
    println!("{}", "=".repeat(60));
    println!("{}", locale.title());
    println!("{}", "=".repeat(60));

    let client = SolanaClient::new(settings.rpc_url.clone())?;
    let detector = MevDetector::new(settings.mev_detection.clone(), settings.language.clone());

    if !settings.auto_detect_hashes.is_empty() {
        println!(
            "{} {}",
            locale.auto_detect_start(),
            settings.auto_detect_hashes.len()
        );

        for (index, hash) in settings.auto_detect_hashes.iter().enumerate() {
            println!("\n{}", "=".repeat(80));
            println!(
                "{} {} / {} - {}",
                locale.auto_detect_progress(),
                index + 1,
                settings.auto_detect_hashes.len(),
                hash
            );
            println!("{}", "=".repeat(80));

            match analyze_transaction(&client, &detector, hash, &locale, &settings).await {
                Ok(_) => {
                    println!("{}", locale.auto_detect_done());
                }
                Err(e) => {
                    error!("{} {}", locale.analysis_failed(), e);
                }
            }
        }

        println!("\n{}", "=".repeat(80));
        println!("{}", locale.all_auto_detect_done());
        println!("{}", "=".repeat(80));
    }

    loop {
        println!("{}", locale.prompt());
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let target_signature = input.trim();

                if target_signature.is_empty() {
                    continue;
                }

                if target_signature.eq_ignore_ascii_case("exit")
                    || target_signature.eq_ignore_ascii_case("quit")
                {
                    println!("{}", locale.exiting());
                    break;
                }

                println!("{} {}", locale.analyzing(), target_signature);
                println!("{}", "-".repeat(50));

                match analyze_transaction(&client, &detector, target_signature, &locale, &settings).await {
                    Ok(_) => {
                        println!("{}", "-".repeat(50));
                        println!("{}", locale.analysis_complete());
                    }
                    Err(e) => {
                        println!("{}", "-".repeat(50));
                        error!("{} {}", locale.analysis_failed(), e);
                    }
                }
            }
            Err(e) => {
                error!("{} {}", locale.reading_input_failed(), e);
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
    locale: &Locale,
    settings: &Settings,
) -> Result<(), Box<dyn std::error::Error>> {
    // 步骤1: 获取目标交易
    let target_tx = match client.get_transaction(target_signature).await {
        Ok(tx) => tx,
        Err(e) => {
            error!("{} {}", locale.get_tx_failed(), e);
            return Err(e.into());
        }
    };

    info!("{} {}", locale.get_tx_success(), target_tx.slot);

    // 步骤2: 检查是否为简单转账
    if detector.is_simple_transfer(&target_tx) {
        println!("{}", locale.simple_transfer());
        return Ok(());
    }

    // 步骤3: 检查是否涉及DEX/Swap交易
    if !detector.is_dex_transaction(&target_tx) {
        println!("此交易不涉及DEX/Swap，无需MEV检测");
        return Ok(());
    }

    println!("{}", locale.swap_detected());

    // 步骤4: 根据配置选择分析方法
    if settings.mev_detection.ignore_jito {
        // 忽略Jito模式 - 直接基于账户重合分析
        println!("🔧 忽略Jito模式已开启，使用账户重合分析方法");
        
        let (nearby_transactions, target_index) = match client.get_nearby_transactions(target_signature).await {
            Ok(result) => result,
            Err(e) => {
                error!("{} {}", locale.get_nearby_failed(), e);
                println!("{}", locale.rpc_suggestion());
                return Err(e.into());
            }
        };

        println!("{}",locale.analyzing_nearby().replace("{}", &nearby_transactions.len().to_string()));
        
        // 基于纯账户重合进行MEV分析（不检查Jito小费）
        analyze_account_overlap_mev(&client, &detector, &nearby_transactions, target_index, target_signature, &locale).await?;
    } else {
        // 正常模式 - 优先使用Jito API查询束包
        let bundle_result = detector.check_jito_bundle_api(target_signature).await;
        
        match bundle_result {
            Some(bundle_info) => {
                // Jito API找到束包，使用束包分析
                println!("🎯 通过Jito API找到束包: {}", bundle_info.bundle_id);
                println!("📦 束包交易数量: {}", bundle_info.transactions.len());
                println!("💰 束包小费: {:.9} SOL", bundle_info.landed_tip_lamports as f64 / 1_000_000_000.0);
                
                // 分析束包中的交易位置
                if let Some(position_analysis) = detector.analyze_bundle_position(&bundle_info, target_signature) {
                    println!("📍 目标交易位置: {} / {}", position_analysis.target_position + 1, position_analysis.total_transactions);
                    
                    // 显示束包内所有交易
                    println!("\n📋 束包内交易列表:");
                    for (i, tx_sig) in bundle_info.transactions.iter().enumerate() {
                        let status = if tx_sig == target_signature {
                            "🎯 目标交易"
                        } else if i < position_analysis.target_position {
                            "⬆️  前置交易"
                        } else {
                            "⬇️  后置交易"
                        };
                        println!("  {}. {} {}", i + 1, &tx_sig[0..8], status);
                    }
                    
                    // 基于束包进行MEV分析
                    analyze_bundle_mev(&client, &detector, &bundle_info, target_signature, &locale).await?;
                }
            }
            None => {
                // Jito API查不到，使用传统方法
                println!("Jito API未找到束包，使用传统分析方法");
                
                let (nearby_transactions, target_index) = match client.get_nearby_transactions(target_signature).await {
                    Ok(result) => result,
                    Err(e) => {
                        error!("{} {}", locale.get_nearby_failed(), e);
                        println!("{}", locale.rpc_suggestion());
                        return Err(e.into());
                    }
                };

                println!("{}",locale.analyzing_nearby().replace("{}", &nearby_transactions.len().to_string()));
                
                // 基于附近交易进行MEV分析
                analyze_traditional_mev(&client, &detector, &nearby_transactions, target_index, target_signature, &locale).await?;
            }
        }
    }

    Ok(())
}

/// 基于束包进行MEV分析
async fn analyze_bundle_mev(
    client: &SolanaClient,
    detector: &MevDetector,
    bundle_info: &crate::mev::JitoBundleInfo,
    target_signature: &str,
    locale: &Locale,
) -> Result<(), Box<dyn std::error::Error>> {
    // 获取束包内的所有交易
    let bundle_transactions = detector.create_bundle_transactions(client, bundle_info).await;
    
    // 检测三明治攻击
    if let Some(sandwich) = detector.detect_sandwich_attack(&bundle_transactions, target_signature) {
        println!("{}", locale.sandwich_detected());
        println!("{}{}", locale.front_tx(), sandwich.front_tx);
        println!("{}{}", locale.back_tx(), sandwich.back_tx);
        
        // 计算损失 - 优先使用余额变化方法
        let loss_result = calculate_mev_loss(client, detector, &sandwich.front_tx, target_signature, &sandwich.back_tx, locale).await;
        
        if let Some(loss) = loss_result {
            display_loss_results(&loss, locale);
        } else {
            println!("{}", locale.cannot_calculate_loss());
        }
    } else if let Some(frontrun) = detector.detect_frontrun_attack(&bundle_transactions, target_signature) {
        println!("{}", locale.frontrun_detected());
        println!("{} {}", locale.frontrun_tx(), frontrun.front_tx);
        
        // 抢跑攻击的损失计算逻辑可以简化或跳过
        println!("抢跑攻击损失计算待实现");
    } else {
        println!("{}", locale.no_mev_detected());
    }
    
    Ok(())
}

/// 基于传统方法进行MEV分析
async fn analyze_traditional_mev(
    client: &SolanaClient,
    detector: &MevDetector,
    nearby_transactions: &[crate::client::Transaction],
    target_index: usize,
    target_signature: &str,
    locale: &Locale,
) -> Result<(), Box<dyn std::error::Error>> {
    let jito_tip_info = detector.check_jito_tip_in_nearby_transactions(nearby_transactions, target_index, target_signature).await;

    match jito_tip_info {
        Some((_tip_index, _tip_account, tip_amount, _is_tip_before_target, bundle_transactions)) => {
            println!("{}", locale.jito_bundle_detected());
            println!("💰 检测到小费: {:.9} SOL", tip_amount as f64 / 1_000_000_000.0);
            
            // 检测三明治攻击
            if let Some(sandwich) = detector.detect_sandwich_attack(&bundle_transactions, target_signature) {
                println!("{}", locale.sandwich_detected());
                println!("{}{}", locale.front_tx(), sandwich.front_tx);
                println!("{}{}", locale.back_tx(), sandwich.back_tx);
                
                // 计算损失
                let loss_result = calculate_mev_loss(client, detector, &sandwich.front_tx, target_signature, &sandwich.back_tx, locale).await;
                
                if let Some(loss) = loss_result {
                    display_loss_results(&loss, locale);
                } else {
                    println!("{}", locale.cannot_calculate_loss());
                }
            } else if let Some(frontrun) = detector.detect_frontrun_attack(&bundle_transactions, target_signature) {
                println!("{}", locale.frontrun_detected());
                println!("{} {}", locale.frontrun_tx(), frontrun.front_tx);
                println!("抢跑攻击损失计算待实现");
            } else {
                println!("{}", locale.no_mev_detected());
            }
        }
        None => {
            println!("{}", locale.no_jito_tip());
            for reason in locale.no_jito_tip_reasons().iter() {
                println!("{}", reason);
            }
        }
    }
    
    Ok(())
}

/// 基于账户重合进行MEV分析 - 忽略Jito模式
async fn analyze_account_overlap_mev(
    client: &SolanaClient,
    detector: &MevDetector,
    nearby_transactions: &[crate::client::Transaction],
    target_index: usize,
    target_signature: &str,
    locale: &Locale,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 分析账户重合模式MEV攻击...");
    
    // 获取目标交易的账户列表
    let target_tx = &nearby_transactions[target_index];
    let target_accounts: Vec<String> = target_tx.transaction.message.account_keys
        .iter()
        .map(|key| key.to_string())
        .collect();
    
    println!("🎯 目标交易涉及 {} 个账户", target_accounts.len());
    
    // 分析前置交易
    let mut potential_front_txs = Vec::new();
    for i in 0..target_index {
        let tx = &nearby_transactions[i];
        let tx_accounts: Vec<String> = tx.transaction.message.account_keys
            .iter()
            .map(|key| key.to_string())
            .collect();
        
        // 计算账户重合度
        let overlap_count = target_accounts.iter()
            .filter(|account| tx_accounts.contains(account))
            .count();
        
        let overlap_ratio = overlap_count as f64 / target_accounts.len() as f64;
        
        // 如果重合度超过阈值，认为可能是前置攻击交易
        if overlap_ratio >= 0.3 && detector.is_dex_transaction(tx) {
            potential_front_txs.push((i, tx.transaction.signatures[0].to_string(), overlap_ratio));
            println!("  ⬆️  前置交易 {}: 重合度 {:.1}%", &tx.transaction.signatures[0].to_string()[0..8], overlap_ratio * 100.0);
        }
    }
    
    // 分析后置交易
    let mut potential_back_txs = Vec::new();
    for i in (target_index + 1)..nearby_transactions.len() {
        let tx = &nearby_transactions[i];
        let tx_accounts: Vec<String> = tx.transaction.message.account_keys
            .iter()
            .map(|key| key.to_string())
            .collect();
        
        // 计算账户重合度
        let overlap_count = target_accounts.iter()
            .filter(|account| tx_accounts.contains(account))
            .count();
        
        let overlap_ratio = overlap_count as f64 / target_accounts.len() as f64;
        
        // 如果重合度超过阈值，认为可能是后置攻击交易
        if overlap_ratio >= 0.3 && detector.is_dex_transaction(tx) {
            potential_back_txs.push((i, tx.transaction.signatures[0].to_string(), overlap_ratio));
            println!("  ⬇️  后置交易 {}: 重合度 {:.1}%", &tx.transaction.signatures[0].to_string()[0..8], overlap_ratio * 100.0);
        }
    }
    
    // 检测三明治攻击 - 需要前置和后置交易都存在
    if !potential_front_txs.is_empty() && !potential_back_txs.is_empty() {
        // 选择重合度最高的前置和后置交易
        let best_front = potential_front_txs.iter().max_by(|a, b| a.2.partial_cmp(&b.2).unwrap()).unwrap();
        let best_back = potential_back_txs.iter().max_by(|a, b| a.2.partial_cmp(&b.2).unwrap()).unwrap();
        
        println!("{}", locale.sandwich_detected());
        println!("{}{}  (重合度: {:.1}%)", locale.front_tx(), best_front.1, best_front.2 * 100.0);
        println!("{}{}  (重合度: {:.1}%)", locale.back_tx(), best_back.1, best_back.2 * 100.0);
        
        // 计算损失
        let loss_result = calculate_mev_loss(client, detector, &best_front.1, target_signature, &best_back.1, locale).await;
        
        if let Some(loss) = loss_result {
            display_loss_results(&loss, locale);
        } else {
            println!("{}", locale.cannot_calculate_loss());
        }
    } else if !potential_front_txs.is_empty() {
        // 只有前置交易，可能是抢跑攻击
        let best_front = potential_front_txs.iter().max_by(|a, b| a.2.partial_cmp(&b.2).unwrap()).unwrap();
        
        println!("{}", locale.frontrun_detected());
        println!("{} {}  (重合度: {:.1}%)", locale.frontrun_tx(), best_front.1, best_front.2 * 100.0);
        println!("抢跑攻击损失计算待实现");
    } else {
        println!("{}", locale.no_mev_detected());
        println!("📊 分析结果: 附近交易与目标交易账户重合度低，未发现明显MEV攻击模式");
    }
    
    Ok(())
}

/// 计算MEV损失 - 简化版本，只使用两种方法
async fn calculate_mev_loss(
    client: &SolanaClient,
    detector: &MevDetector,
    front_tx_sig: &str,
    target_tx_sig: &str,
    back_tx_sig: &str,
    _locale: &Locale,
) -> Option<crate::mev::UserLoss> {
    // 方法1: 优先使用余额变化分析
    if let Some(loss) = detector.calculate_precise_sandwich_loss(client, front_tx_sig, target_tx_sig, back_tx_sig).await {
        return Some(loss);
    }
    
    // 方法2: 回退到指令解析分析
    if let Some(loss) = detector.calculate_instruction_based_loss(client, front_tx_sig, target_tx_sig, back_tx_sig).await {
        return Some(loss);
    }
    
    None
}

/// 显示损失结果
fn display_loss_results(loss: &crate::mev::UserLoss, locale: &Locale) {
    println!("\n {}", locale.user_loss_estimation());
    
    // 使用攻击者获利的单位来显示用户损失
    if let Some(profit_token) = &loss.mev_profit_token {
        if profit_token != "SOL" {
            // 攻击者获利是其他代币，用户损失也用该代币单位显示
            let user_loss_amount = loss.mev_profit_amount * 0.9; // 用户损失约为攻击者获利的90%
            let sol_equivalent = loss.mev_profit_lamports as f64 * 0.9 / 1_000_000_000.0;
            println!(
                "  {} {:.6} {} ({:.9}个SOL)",
                locale.loss_amount(),
                user_loss_amount,
                profit_token,
                sol_equivalent
            );
        } else {
            // 攻击者获利是SOL，用户损失也用SOL显示
            let user_loss_sol = loss.mev_profit_amount * 0.9; // 用户损失约为攻击者获利的90%
            println!(
                "  {} {:.9} SOL",
                locale.loss_amount(),
                user_loss_sol
            );
        }
    } else {
        // 没有攻击者获利信息，使用保守估算
        let conservative_loss = loss.mev_profit_lamports as f64 * 0.9 / 1_000_000_000.0;
        println!(
            "  {} {:.9} SOL",
            locale.loss_amount(),
            conservative_loss
        );
    }
    
    println!("  {} {:.2}%", locale.loss_percentage(), loss.loss_percentage);
    
    // 显示攻击者利润
    if let Some(profit_token) = &loss.mev_profit_token {
        if profit_token == "SOL" {
            println!(
                "  {} {:.9} SOL",
                locale.mev_profit(),
                loss.mev_profit_amount
            );
        } else {
            println!(
                "  {} {:.6} {}",
                locale.mev_profit(),
                loss.mev_profit_amount,
                profit_token
            );
        }
    } else {
        println!(
            "  {} {:.9} SOL",
            locale.mev_profit(),
            loss.mev_profit_lamports as f64 / 1_000_000_000.0
        );
    }
    
    println!("  {} {}", locale.calculation_method(), loss.calculation_method);
    
    // 显示置信度和验证信息
    let confidence_icon = if loss.confidence_score >= 0.8 {
        "🟢"
    } else if loss.confidence_score >= 0.6 {
        "🟡"
    } else {
        "🔴"
    };
    println!("  {} Confidence: {:.1}%", confidence_icon, loss.confidence_score * 100.0);
    
    let validation_icon = if loss.validation_passed { "✅" } else { "⚠️" };
    println!("  {} Validation: {}", validation_icon, if loss.validation_passed { "Passed" } else { "Failed" });

    // 显示具体的代币损失信息（基于攻击者获利重新计算）
    if !loss.token_losses.is_empty() {
        println!("\n📊 Token Loss Details:");
        for (i, token_loss) in loss.token_losses.iter().enumerate() {
            let is_primary = loss.primary_loss_token.as_ref() == Some(&token_loss.token_address);
            let primary_indicator = if is_primary { " (Primary)" } else { "" };
            
            // 根据攻击者获利重新计算合理的损失
            if token_loss.token_symbol == "SOL" {
                let realistic_sol_loss = loss.mev_profit_lamports as f64 * 0.9 / 1_000_000_000.0;
                if loss.mev_profit_token.as_ref() != Some(&"SOL".to_string()) {
                    if let Some(profit_token) = &loss.mev_profit_token {
                        println!(
                            "  {}. {} Loss: {:.9} {} ({:.6}个{}){}", 
                            i + 1,
                            token_loss.token_symbol,
                            realistic_sol_loss,
                            token_loss.token_symbol,
                            loss.mev_profit_amount * 0.9,
                            profit_token,
                            primary_indicator
                        );
                    } else {
                        println!(
                            "  {}. {} Loss: {:.9} {}{}", 
                            i + 1,
                            token_loss.token_symbol,
                            realistic_sol_loss,
                            token_loss.token_symbol,
                            primary_indicator
                        );
                    }
                } else {
                    println!(
                        "  {}. {} Loss: {:.9} {}{}", 
                        i + 1,
                        token_loss.token_symbol,
                        realistic_sol_loss,
                        token_loss.token_symbol,
                        primary_indicator
                    );
                }
            } else {
                // 对于其他代币，使用攻击者获利的90%
                let realistic_token_loss = if loss.mev_profit_token.as_ref() == Some(&token_loss.token_symbol) {
                    loss.mev_profit_amount * 0.9
                } else {
                    token_loss.loss_amount_ui
                };
                println!(
                    "  {}. {} Loss: {:.9} {}{}", 
                    i + 1,
                    token_loss.token_symbol,
                    realistic_token_loss,
                    token_loss.token_symbol,
                    primary_indicator
                );
            }
        }
    }
}