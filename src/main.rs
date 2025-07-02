use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio;
use reqwest;
use std::time::Duration;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Transaction {
    #[serde(default)]
    signature: String,
    slot: u64,
    #[serde(rename = "blockTime")]
    block_time: Option<i64>,
    transaction: TransactionData,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TransactionData {
    message: Message,
    signatures: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Message {
    #[serde(rename = "accountKeys")]
    account_keys: Vec<String>,
    instructions: Vec<Instruction>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Instruction {
    #[serde(rename = "programId")]
    program_id: Option<String>,
    accounts: Vec<u8>,
    data: String,
}

#[derive(Debug, Clone)]
struct SandwichDetails {
    front_tx: String,
    back_tx: String,
    profit_estimate: f64,
}

#[derive(Debug, Clone)]
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
    fn new(rpc_url: String) -> Result<Self, reqwest::Error> {
        Ok(Self {
            rpc_url,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        })
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
        
        if let Some(result) = json.get("result") {
            let mut tx: Transaction = serde_json::from_value(result.clone())?;
            if let Some(s) = tx.transaction.signatures.first() {
                tx.signature = s.clone();
            }
            Ok(tx)
        } else {
            Err(format!("Transaction not found or error in response: {}", json).into())
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
        
        if let Some(result) = json.get("result") {
             if let Some(signatures) = result.get("signatures").and_then(|s| s.as_array()) {
                let sigs: Vec<String> = signatures
                    .iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect();
                return Ok(sigs);
            }
        }
        
        Ok(vec![])
    }

    async fn get_surrounding_transactions(&self, target_signature: &str, target_slot: u64) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
        let mut all_transactions_to_analyze = Vec::new();
        
        let slot = target_slot;
        println!("[DEBUG] 正在获取目标区块 {} 的所有交易签名...", slot);
        let block_signatures = match self.get_block_transactions(slot).await {
            Ok(sigs) => {
                println!("[DEBUG] 区块 {} 获取到 {} 个签名。", slot, sigs.len());
                sigs
            },
            Err(e) => {
                println!("[WARN] 无法获取区块 {} 的交易签名: {}", slot, e);
                return Ok(vec![]);
            }
        };

        if let Some(target_index) = block_signatures.iter().position(|s| s == target_signature) {
            println!("[DEBUG] 目标交易签名在区块中的索引为: {}", target_index);
            let start_index = target_index.saturating_sub(5);
            let end_index = std::cmp::min(target_index + 6, block_signatures.len());

            println!("[DEBUG] 确定需要获取详细信息的交易签名范围: [{}, {})", start_index, end_index);

            for i in start_index..end_index {
                let sig = &block_signatures[i];
                println!("[DEBUG] 正在获取选定交易详情: {}", sig);
                if let Ok(tx) = self.get_transaction(sig).await {
                    all_transactions_to_analyze.push(tx);
                } else {
                    println!("[WARN] 无法获取选定交易详情: {}", sig);
                }
            }
        } else {
            println!("[WARN] 未在区块 {} 的交易签名列表中找到目标交易签名。", slot);
            // 如果目标交易不在当前区块签名列表中，则尝试获取目标交易本身
            if let Ok(tx) = self.get_transaction(target_signature).await {
                all_transactions_to_analyze.push(tx);
                println!("[INFO] 仅获取了目标交易本身进行分析。");
            } else {
                println!("[ERROR] 无法获取目标交易本身。");
            }
        }

        all_transactions_to_analyze.sort_by(|a, b| {
            match (a.block_time, b.block_time) {
                (Some(time_a), Some(time_b)) => time_a.cmp(&time_b),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.slot.cmp(&b.slot),
            }
        });

        println!("[INFO] 最终将分析 {} 笔交易。", all_transactions_to_analyze.len());
        Ok(all_transactions_to_analyze)
    }
}

struct MevDetector;

impl MevDetector {
    fn detect_sandwich_attack(&self, transactions: &[Transaction], target_signature: &str) -> Option<SandwichDetails> {
        let target_index = transactions.iter().position(|tx| tx.signature == target_signature)?;
        
        for i in 0..target_index {
            for j in (target_index + 1)..transactions.len() {
                let front_tx = &transactions[i];
                let back_tx = &transactions[j];
                
                if self.is_same_attacker(&front_tx, &back_tx) {
                    if self.targets_same_token_pair(&front_tx, &back_tx, &transactions[target_index]) {
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
        
        for i in (0..target_index).rev() {
            let potential_frontrun = &transactions[i];
            
            if let (Some(frontrun_time), Some(target_time)) = (potential_frontrun.block_time, target_tx.block_time) {
                let time_diff = target_time - frontrun_time;
                
                if time_diff < 5000 && // 5 seconds
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
        if let (Some(signer1), Some(signer2)) = (
            tx1.transaction.message.account_keys.first(),
            tx2.transaction.message.account_keys.first()
        ) {
            return signer1 == signer2;
        }
        false
    }

    fn targets_same_token_pair(&self, tx1: &Transaction, tx2: &Transaction, target_tx: &Transaction) -> bool {
        let tx1_programs: std::collections::HashSet<String> = tx1.transaction.message.instructions
            .iter().filter_map(|i| i.program_id.clone()).collect();
        let tx2_programs: std::collections::HashSet<String> = tx2.transaction.message.instructions
            .iter().filter_map(|i| i.program_id.clone()).collect();
        let target_programs: std::collections::HashSet<String> = target_tx.transaction.message.instructions
            .iter().filter_map(|i| i.program_id.clone()).collect();

        let dex_programs = vec![
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM
            "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP", // Orca
            "22Y43yTVxuUkoRKdm9thyRhQ3SdgQS7c7kB6UNCiaczD", // Serum DEX
        ];

        for dex in &dex_programs {
            if tx1_programs.contains(*dex) && tx2_programs.contains(*dex) && target_programs.contains(*dex) {
                return true;
            }
        }

        false
    }

    fn targets_same_token_pair_simple(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        let tx1_programs: std::collections::HashSet<String> = tx1.transaction.message.instructions
            .iter().filter_map(|i| i.program_id.clone()).collect();
        let tx2_programs: std::collections::HashSet<String> = tx2.transaction.message.instructions
            .iter().filter_map(|i| i.program_id.clone()).collect();

        !tx1_programs.is_disjoint(&tx2_programs)
    }

    fn has_opposite_operations(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        if let (Some(inst1), Some(inst2)) = (
            tx1.transaction.message.instructions.first(),
            tx2.transaction.message.instructions.first()
        ) {
            return inst1.data != inst2.data;
        }
        false
    }

    fn has_similar_operations(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        if let (Some(inst1), Some(inst2)) = (
            tx1.transaction.message.instructions.first(),
            tx2.transaction.message.instructions.first()
        ) {
            if let (Some(prog1), Some(prog2)) = (&inst1.program_id, &inst2.program_id) {
                return prog1 == prog2;
            }
        }
        false
    }

    fn estimate_sandwich_profit(&self, _front_tx: &Transaction, _back_tx: &Transaction) -> f64 {
        0.01
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://mainnet.helius-rpc.com/?api-key=5e4bda23-d6c1-4e7e-9421-3bcab57692b0".to_string();
    let client = SolanaClient::new(rpc_url)?;
    let detector = MevDetector;

    println!("[INFO] 步骤1: 等待输入Solana交易哈希...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let target_signature = input.trim();

    if target_signature.is_empty() {
        println!("[WARN] 未输入交易哈希，程序退出。");
        return Ok(());
    }

    println!("[INFO] 步骤2: 正在分析交易: {}", target_signature);

    match client.get_transaction(target_signature).await {
        Ok(target_tx) => {
            println!("[INFO] 步骤3: 成功获取目标交易信息。交易所在区块: {}", target_tx.slot);
            
            println!("[INFO] 步骤4: 正在获取周边交易...");
            match client.get_surrounding_transactions(target_signature, target_tx.slot).await {
                Ok(surrounding_txs) => {
                    println!("[INFO] 步骤5: 成功获取到 {} 笔相关交易进行分析", surrounding_txs.len());
                    
                    println!("[INFO] 步骤6: 正在检测三明治攻击...");
                    if let Some(sandwich) = detector.detect_sandwich_attack(&surrounding_txs, target_signature) {
                        println!("[ALERT] 🚨 检测到三明治攻击!");
                        println!("  前置交易: https://solscan.io/tx/{}", sandwich.front_tx);
                        println!("  后置交易: https://solscan.io/tx/{}", sandwich.back_tx);
                        println!("  估算利润: {:.2}%", sandwich.profit_estimate * 100.0);
                    } else {
                        println!("[INFO] ✅ 未检测到三明治攻击");
                    }
                    
                    println!("[INFO] 步骤7: 正在检测抢跑攻击...");
                    if let Some(frontrun) = detector.detect_frontrun_attack(&surrounding_txs, target_signature) {
                        println!("[ALERT] 🚨 检测到抢跑攻击!");
                        println!("  抢跑交易: https://solscan.io/tx/{}", frontrun.frontrun_tx);
                        println!("  受害交易: https://solscan.io/tx/{}", frontrun.victim_tx);
                        println!("  时间差: {} 毫秒", frontrun.time_difference_ms);
                    } else {
                        println!("[INFO] ✅ 未检测到抢跑攻击");
                    }
                }
                Err(e) => println!("[ERROR] 获取周围交易失败: {}", e),
            }
        }
        Err(e) => println!("[ERROR] 获取交易失败: {}", e),
    }

    Ok(())
}