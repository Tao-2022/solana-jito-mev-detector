use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tokio;
use reqwest;

#[derive(Debug, Deserialize, Serialize)]
struct Transaction {
    signature: String,
    slot: u64,
    block_time: Option<i64>,
    transaction: TransactionData,
}

#[derive(Debug, Deserialize, Serialize)]
struct TransactionData {
    message: Message,
}

#[derive(Debug, Deserialize, Serialize)]
struct Message {
    #[serde(rename = "accountKeys")]
    account_keys: Vec<String>,
    instructions: Vec<Instruction>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Instruction {
    #[serde(rename = "programId")]
    program_id: String,
    accounts: Vec<u8>,
    data: String,
}

#[derive(Debug)]
struct AttackResult {
    is_sandwich: bool,
    is_frontrun: bool,
    sandwich_details: Option<SandwichDetails>,
    frontrun_details: Option<FrontrunDetails>,
}

#[derive(Debug)]
struct SandwichDetails {
    front_tx: String,
    back_tx: String,
    profit_estimate: f64,
}

#[derive(Debug)]
struct FrontrunDetails {
    frontrun_tx: String,
    victim_tx: String,
    time_difference_ms: i64,
}

struct SolanaClient {
    rpc_url: String,
    client: reqwest::Client,
}

impl SolanaClient {
    fn new(rpc_url: String) -> Self {
        Self {
            rpc_url,
            client: reqwest::Client::new(),
        }
    }

    async fn get_transaction(&self, signature: &str) -> Result<Transaction, Box<dyn std::error::Error>> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "json",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        });

        let response = self.client
            .post(&self.rpc_url)
            .json(&request_body)
            .send()
            .await?;

        let json: Value = response.json().await?;
        
        if let Some(result) = json["result"].as_object() {
            let transaction = Transaction {
                signature: signature.to_string(),
                slot: result["slot"].as_u64().unwrap_or(0),
                block_time: result["blockTime"].as_i64(),
                transaction: serde_json::from_value(result["transaction"].clone())?,
            };
            Ok(transaction)
        } else {
            Err("Transaction not found".into())
        }
    }

    async fn get_block_transactions(&self, slot: u64) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlock",
            "params": [
                slot,
                {
                    "encoding": "json",
                    "transactionDetails": "signatures",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        });

        let response = self.client
            .post(&self.rpc_url)
            .json(&request_body)
            .send()
            .await?;

        let json: Value = response.json().await?;
        
        if let Some(result) = json["result"].as_object() {
            if let Some(transactions) = result["transactions"].as_array() {
                let signatures: Vec<String> = transactions
                    .iter()
                    .filter_map(|tx| tx.as_str().map(|s| s.to_string()))
                    .collect();
                return Ok(signatures);
            }
        }
        
        Ok(vec![])
    }

    async fn get_surrounding_transactions(&self, target_signature: &str, target_slot: u64) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
        let mut all_transactions = Vec::new();
        
        // 获取目标slot和前后几个slot的交易
        for slot_offset in -2i64..=2i64 {
            let slot = (target_slot as i64 + slot_offset) as u64;
            if let Ok(signatures) = self.get_block_transactions(slot).await {
                for sig in signatures {
                    if let Ok(tx) = self.get_transaction(&sig).await {
                        all_transactions.push(tx);
                    }
                }
            }
        }

        // 按时间排序
        all_transactions.sort_by(|a, b| {
            match (&a.block_time, &b.block_time) {
                (Some(time_a), Some(time_b)) => time_a.cmp(time_b),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.slot.cmp(&b.slot),
            }
        });

        // 找到目标交易的位置并获取前后5笔交易
        if let Some(target_index) = all_transactions.iter().position(|tx| tx.signature == target_signature) {
            let start = target_index.saturating_sub(5);
            let end = std::cmp::min(target_index + 6, all_transactions.len());
            return Ok(all_transactions[start..end].to_vec());
        }

        Ok(all_transactions)
    }
}

struct MevDetector;

impl MevDetector {
    fn detect_sandwich_attack(&self, transactions: &[Transaction], target_signature: &str) -> Option<SandwichDetails> {
        let target_index = transactions.iter().position(|tx| tx.signature == target_signature)?;
        
        // 寻找三明治攻击模式：相同账户在目标交易前后进行相反操作
        for i in 0..target_index {
            for j in (target_index + 1)..transactions.len() {
                let front_tx = &transactions[i];
                let back_tx = &transactions[j];
                
                // 检查是否为同一个攻击者
                if self.is_same_attacker(&front_tx, &back_tx) {
                    // 检查是否操作了相同的代币对
                    if self.targets_same_token_pair(&front_tx, &back_tx, &transactions[target_index]) {
                        // 检查操作方向是否相反（买入-卖出或卖出-买入）
                        if self.has_opposite_operations(&front_tx, &back_tx) {
                            return Some(SandwichDetails {
                                front_tx: front_tx.signature.clone(),
                                back_tx: back_tx.signature.clone(),
                                profit_estimate: self.estimate_sandwich_profit(&front_tx, &back_tx),
                            });
                        }
                    }
                }
            }
        }
        
        None
    }

    fn detect_frontrun_attack(&self, transactions: &[Transaction], target_signature: &str) -> Option<FrontrunDetails> {
        let target_index = transactions.iter().position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];
        
        // 检查目标交易前的交易
        for i in (0..target_index).rev() {
            let potential_frontrun = &transactions[i];
            
            // 检查时间差（抢跑通常在很短时间内发生）
            if let (Some(frontrun_time), Some(target_time)) = (potential_frontrun.block_time, target_tx.block_time) {
                let time_diff = target_time - frontrun_time;
                
                // 如果时间差很小且操作类似，可能是抢跑
                if time_diff < 5000 && // 5秒内
                   self.has_similar_operations(potential_frontrun, target_tx) &&
                   self.targets_same_token_pair_simple(potential_frontrun, target_tx) {
                    return Some(FrontrunDetails {
                        frontrun_tx: potential_frontrun.signature.clone(),
                        victim_tx: target_tx.signature.clone(),
                        time_difference_ms: time_diff * 1000,
                    });
                }
            }
        }
        
        None
    }

    fn is_same_attacker(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        // 检查交易的第一个账户（通常是签名者）是否相同
        if let (Some(signer1), Some(signer2)) = (
            tx1.transaction.message.account_keys.first(),
            tx2.transaction.message.account_keys.first()
        ) {
            return signer1 == signer2;
        }
        false
    }

    fn targets_same_token_pair(&self, tx1: &Transaction, tx2: &Transaction, target_tx: &Transaction) -> bool {
        // 简化版本：检查是否涉及相同的程序和账户
        let tx1_programs: std::collections::HashSet<_> = tx1.transaction.message.instructions
            .iter().map(|i| &i.program_id).collect();
        let tx2_programs: std::collections::HashSet<_> = tx2.transaction.message.instructions
            .iter().map(|i| &i.program_id).collect();
        let target_programs: std::collections::HashSet<_> = target_tx.transaction.message.instructions
            .iter().map(|i| &i.program_id).collect();

        // 检查是否都涉及DEX程序（如Raydium, Orca等）
        let dex_programs = vec![
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM
            "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP", // Orca
            "22Y43yTVxuUkoRKdm9thyRhQ3SdgQS7c7kB6UNCiaczD", // Serum DEX
        ];

        for dex in &dex_programs {
            if tx1_programs.contains(dex) && tx2_programs.contains(dex) && target_programs.contains(dex) {
                return true;
            }
        }

        false
    }

    fn targets_same_token_pair_simple(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        // 简化版本的代币对检查
        let tx1_programs: std::collections::HashSet<_> = tx1.transaction.message.instructions
            .iter().map(|i| &i.program_id).collect();
        let tx2_programs: std::collections::HashSet<_> = tx2.transaction.message.instructions
            .iter().map(|i| &i.program_id).collect();

        // 检查共同的DEX程序
        !tx1_programs.is_disjoint(&tx2_programs)
    }

    fn has_opposite_operations(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        // 这里需要更复杂的逻辑来分析具体的交易指令
        // 简化版本：假设不同的指令数据表示不同的操作
        if let (Some(inst1), Some(inst2)) = (
            tx1.transaction.message.instructions.first(),
            tx2.transaction.message.instructions.first()
        ) {
            return inst1.data != inst2.data;
        }
        false
    }

    fn has_similar_operations(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        // 检查是否有相似的操作（抢跑通常是相同类型的操作）
        if let (Some(inst1), Some(inst2)) = (
            tx1.transaction.message.instructions.first(),
            tx2.transaction.message.instructions.first()
        ) {
            return inst1.program_id == inst2.program_id;
        }
        false
    }

    fn estimate_sandwich_profit(&self, _front_tx: &Transaction, _back_tx: &Transaction) -> f64 {
        // 简化版本：返回估算利润
        // 实际实现需要分析代币余额变化
        0.01 // 假设1%的利润
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Solana RPC端点
    let rpc_url = "https://api.mainnet-beta.solana.com".to_string();
    let client = SolanaClient::new(rpc_url);
    let detector = MevDetector;

    // 示例：检测指定交易哈希
    println!("请输入要检测的Solana交易哈希:");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let target_signature = input.trim();

    println!("正在分析交易: {}", target_signature);

    // 获取目标交易信息
    match client.get_transaction(target_signature).await {
        Ok(target_tx) => {
            println!("交易所在区块: {}", target_tx.slot);
            
            // 获取周围的交易
            match client.get_surrounding_transactions(target_signature, target_tx.slot).await {
                Ok(surrounding_txs) => {
                    println!("获取到 {} 笔相关交易", surrounding_txs.len());
                    
                    // 检测三明治攻击
                    if let Some(sandwich) = detector.detect_sandwich_attack(&surrounding_txs, target_signature) {
                        println!("🚨 检测到三明治攻击!");
                        println!("  前置交易: {}", sandwich.front_tx);
                        println!("  后置交易: {}", sandwich.back_tx);
                        println!("  估算利润: {:.2}%", sandwich.profit_estimate * 100.0);
                    } else {
                        println!("✅ 未检测到三明治攻击");
                    }
                    
                    // 检测抢跑攻击
                    if let Some(frontrun) = detector.detect_frontrun_attack(&surrounding_txs, target_signature) {
                        println!("🚨 检测到抢跑攻击!");
                        println!("  抢跑交易: {}", frontrun.frontrun_tx);
                        println!("  时间差: {} 毫秒", frontrun.time_difference_ms);
                    } else {
                        println!("✅ 未检测到抢跑攻击");
                    }
                }
                Err(e) => println!("获取周围交易失败: {}", e),
            }
        }
        Err(e) => println!("获取交易失败: {}", e),
    }

    Ok(())
}