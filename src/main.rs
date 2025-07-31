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

    let client = SolanaClient::new(settings.rpc_url)?;
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

            match analyze_transaction(&client, &detector, hash, &locale).await {
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

                match analyze_transaction(&client, &detector, target_signature, &locale).await {
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
) -> Result<(), Box<dyn std::error::Error>> {
    let target_tx = match client.get_transaction(target_signature).await {
        Ok(tx) => tx,
        Err(e) => {
            error!("{} {}", locale.get_tx_failed(), e);
            return Err(e.into());
        }
    };

    info!("{} {}", locale.get_tx_success(), target_tx.slot);

    if detector.is_simple_transfer(&target_tx) {
        println!("{}", locale.simple_transfer());
        return Ok(());
    }

    println!("{}", locale.swap_detected());

    let (nearby_transactions, target_index) =
        match client.get_nearby_transactions(target_signature).await {
            Ok(result) => result,
            Err(e) => {
                error!("{} {}", locale.get_nearby_failed(), e);
                println!("{}", locale.rpc_suggestion());
                return Err(e.into());
            }
        };

    println!(
        "{}",
        locale.analyzing_nearby()
            .replace("{}", &nearby_transactions.len().to_string())
    );

    let jito_tip_info =
        detector.check_jito_tip_in_nearby_transactions(&nearby_transactions, target_index);

    match jito_tip_info {
        Some((tip_index, _tip_account, tip_amount, is_tip_before_target, bundle_transactions)) => {
            println!("{}", locale.jito_bundle_detected());

            let tip_position = if is_tip_before_target {
                locale.tip_location_before()
            } else {
                locale.tip_location_after()
            };
            println!("{}", locale.tip_location().replace("{}", tip_position));
            println!(
                "{} {:.9} SOL",
                locale.tip_amount(),
                tip_amount as f64 / 1_000_000_000.0
            );

            println!(
                "{}",
                locale.bundle_contains()
                    .replace("{}", &bundle_transactions.len().to_string())
            );
            for (i, tx) in bundle_transactions.iter().enumerate() {
                if tx.signature == nearby_transactions[tip_index].signature {
                    println!("  {}{}", i + 1, locale.jito_tip_tx());
                } else if tx.signature == target_signature {
                    println!("  {}{}", i + 1, locale.target_tx());
                } else {
                    println!("  {}{}", i + 1, locale.other_tx());
                }
            }

            if let Some(sandwich) =
                detector.detect_sandwich_attack(&bundle_transactions, target_signature)
            {
                println!("{}", locale.sandwich_detected());
                println!("{}{}", locale.front_tx(), sandwich.front_tx);
                println!("{}{}", locale.back_tx(), sandwich.back_tx);
                println!(
                    "{} {}",
                    locale.shared_accounts(),
                    sandwich.account_intersection.len()
                );

                // 优先使用精确余额变化分析，如果失败则尝试指令解析分析
                let mut loss_result = detector.calculate_precise_sandwich_loss(
                    &client,
                    &sandwich.front_tx,
                    target_signature,
                    &sandwich.back_tx,
                ).await;
                
                // 如果精确分析失败，尝试指令解析分析
                if loss_result.is_none() {
                    loss_result = detector.calculate_instruction_based_loss(
                        &client,
                        &sandwich.front_tx,
                        target_signature,
                        &sandwich.back_tx,
                    ).await;
                }
                
                if let Some(loss) = loss_result {
                    println!("{}", locale.user_loss_estimation());
                    
                    // 智能选择显示单位：使用主要损失token的单位
                    if let Some(primary_token_address) = &loss.primary_loss_token {
                        if let Some(primary_token_loss) = loss.token_losses.iter()
                            .find(|t| &t.token_address == primary_token_address) {
                            // 如果主要损失不是SOL，则使用该token的单位显示
                            if primary_token_loss.token_symbol != "SOL" {
                                println!(
                                    "{} {:.6} {}",
                                    locale.loss_amount(),
                                    primary_token_loss.loss_amount_ui,
                                    primary_token_loss.token_symbol
                                );
                            } else {
                                println!(
                                    "{} {:.9} SOL",
                                    locale.loss_amount(),
                                    loss.estimated_loss_lamports as f64 / 1_000_000_000.0
                                );
                            }
                        } else {
                            // 默认SOL显示
                            println!(
                                "{} {:.9} SOL",
                                locale.loss_amount(),
                                loss.estimated_loss_lamports as f64 / 1_000_000_000.0
                            );
                        }
                    } else {
                        // 没有主要token，默认SOL显示
                        println!(
                            "{} {:.9} SOL",
                            locale.loss_amount(),
                            loss.estimated_loss_lamports as f64 / 1_000_000_000.0
                        );
                    }
                    
                    println!("{} {:.2}%", locale.loss_percentage(), loss.loss_percentage);
                    
                    // 智能显示攻击者利润：使用主要利润token的单位
                    if let Some(profit_token) = &loss.mev_profit_token {
                        if profit_token == "SOL" {
                            println!(
                                "{} {:.9} SOL",
                                locale.mev_profit(),
                                loss.mev_profit_amount
                            );
                        } else {
                            println!(
                                "{} {:.6} {}",
                                locale.mev_profit(),
                                loss.mev_profit_amount,
                                profit_token
                            );
                        }
                    } else {
                        // 默认SOL显示
                        println!(
                            "{} {:.9} SOL",
                            locale.mev_profit(),
                            loss.mev_profit_lamports as f64 / 1_000_000_000.0
                        );
                    }
                    println!("{} {}", locale.calculation_method(), loss.calculation_method);
                    
                    // 显示新的置信度和验证信息
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

                    // 显示具体的代币损失信息（如果可用）
                    if !loss.token_losses.is_empty() {
                        println!("\n📊 Token Loss Details:");
                        for (i, token_loss) in loss.token_losses.iter().enumerate() {
                            let is_primary = loss.primary_loss_token.as_ref() == Some(&token_loss.token_address);
                            let primary_indicator = if is_primary { " (Primary)" } else { "" };
                            
                            println!(
                                "  {}. {} {}: {:.9} {}{}", 
                                i + 1,
                                token_loss.token_symbol,
                                "Loss",
                                token_loss.loss_amount_ui,
                                token_loss.token_symbol,
                                primary_indicator
                            );
                        }
                    }
                } else {
                    println!("{}", locale.cannot_calculate_loss());
                }

                println!("{}", locale.frontrun_skipped());
            } else {
                if let Some(frontrun) =
                    detector.detect_frontrun_attack(&bundle_transactions, target_signature)
                {
                    println!("{}", locale.frontrun_detected());
                    println!("{} {}", locale.frontrun_tx(), frontrun.front_tx);
                    println!(
                        "{} {}",
                        locale.shared_accounts(),
                        frontrun.account_intersection.len()
                    );
                } else {
                    println!("{}", locale.no_mev_detected());
                }
            }

            println!("{}", locale.note());
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