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

    /// 获取指定区块的完整信息，包含所有交易详情。
    ///
    /// # 参数
    /// - `slot`: 区块号。
    ///
    /// # 返回
    /// `Result`，包含该区块所有交易的`Transaction`结构体向量或错误信息。
    pub async fn get_full_block(&self, slot: u64) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlock",
            "params": [
                slot,
                {
                    "encoding": "json",
                    "transactionDetails": "full",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        });

        let response = self.client.post(&self.rpc_url).json(&request_body).send().await?;
        let json: Value = response.json().await?;

        if let Some(result) = json.get("result") {
            let block_time: Option<i64> = result.get("blockTime").and_then(|v| v.as_i64());
            
            if let Some(txs_json) = result.get("transactions") {
                let mut transactions = Vec::new();
                if let Some(txs_array) = txs_json.as_array() {
                    for tx_json in txs_array {
                        if let Some(tx_data_json) = tx_json.get("transaction") {
                            if let Ok(tx_data) = serde_json::from_value::<TransactionData>(tx_data_json.clone()) {
                                let signature = tx_data.signatures.first().cloned().unwrap_or_default();
                                let tx = Transaction {
                                    signature,
                                    slot,
                                    block_time,
                                    transaction: tx_data,
                                };
                                transactions.push(tx);
                            }
                        }
                    }
                }
                return Ok(transactions);
            }
        }

        Err(format!("Failed to parse full block or block not found: {}", json).into())
    }
}
