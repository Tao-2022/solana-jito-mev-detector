use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use reqwest::Client;


#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Transaction {
    #[serde(default)]
    pub signature: String,
    pub slot: u64,
    #[serde(rename = "blockTime")]
    pub block_time: Option<i64>,
    pub transaction: TransactionData,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TransactionData {
    pub message: Message,
    pub signatures: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Message {
    #[serde(rename = "accountKeys")]
    pub account_keys: Vec<String>,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Instruction {
    #[serde(rename = "programId")]
    pub program_id: Option<String>,
    pub accounts: Vec<u8>,
    pub data: String,
}

pub struct SolanaClient {
    rpc_url: String,
    client: Client,
}

impl SolanaClient {
    /// 创建一个新的Solana客户端实例。
    ///
    /// # 参数
    /// - `rpc_url`: Solana RPC节点的URL。
    ///
    /// # 返回
    /// `Result`，包含`SolanaClient`实例或`reqwest::Error`。
    pub fn new(rpc_url: String) -> Result<Self, reqwest::Error> {
        Ok(Self {
            rpc_url,
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        })
    }

    /// 获取指定签名的Solana交易详情。
    ///
    /// # 参数
    /// - `signature`: 交易签名（哈希）。
    ///
    /// # 返回
    /// `Result`，包含`Transaction`结构体或错误信息。
    pub async fn get_transaction(&self, signature: &str) -> Result<Transaction, Box<dyn std::error::Error>> {
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

        let response = self.client.post(&self.rpc_url).json(&request_body).send().await?;
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

    /// 获取指定区块号的所有交易签名。
    ///
    /// # 参数
    /// - `slot`: 区块号。
    ///
    /// # 返回
    /// `Result`，包含交易签名字符串向量或错误信息。
    pub async fn get_block_transactions(&self, slot: u64) -> Result<Vec<String>, Box<dyn std::error::Error>> {
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

        let response = self.client.post(&self.rpc_url).json(&request_body).send().await?;
        let json: Value = response.json().await?;

        if let Some(result) = json.get("result") {
            if let Some(signatures) = result.get("signatures").and_then(|s| s.as_array()) {
                return Ok(signatures.iter().filter_map(|s| s.as_str().map(String::from)).collect());
            }
        }

        Ok(vec![])
    }

    /// 获取目标交易周围的相关交易。
    ///
    /// # 参数
    /// - `target_signature`: 目标交易的签名。
    /// - `target_slot`: 目标交易所在的区块号。
    ///
    /// # 返回
    /// `Result`，包含相关交易的`Transaction`结构体向量或错误信息。
    pub async fn get_surrounding_transactions(&self, target_signature: &str, target_slot: u64) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
        let mut all_transactions = Vec::new();
        let block_signatures = self.get_block_transactions(target_slot).await?;

        if let Some(target_index) = block_signatures.iter().position(|s| s == target_signature) {
            let start = target_index.saturating_sub(5);
            let end = (target_index + 6).min(block_signatures.len());

            for sig in &block_signatures[start..end] {
                if let Ok(tx) = self.get_transaction(sig).await {
                    all_transactions.push(tx);
                }
            }
        } else {
            if let Ok(tx) = self.get_transaction(target_signature).await {
                all_transactions.push(tx);
            }
        }

        all_transactions.sort_by(|a, b| {
            match (a.block_time, b.block_time) {
                (Some(ta), Some(tb)) => ta.cmp(&tb),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.slot.cmp(&b.slot),
            }
        });

        Ok(all_transactions)
    }
}
