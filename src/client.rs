use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

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
    #[serde(rename = "recentBlockhash")]
    pub recent_blockhash: Option<String>,
    pub header: Option<MessageHeader>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MessageHeader {
    #[serde(rename = "numRequiredSignatures")]
    pub num_required_signatures: u8,
    #[serde(rename = "numReadonlySignedAccounts")]
    pub num_readonly_signed_accounts: u8,
    #[serde(rename = "numReadonlyUnsignedAccounts")]
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Instruction {
    #[serde(rename = "programIdIndex")]
    pub program_id_index: u8,
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
            client: Client::builder().timeout(Duration::from_secs(30)).build()?,
        })
    }

    /// 判断指定索引的账户是否可写
    pub fn is_account_writable(&self, account_index: usize, message: &Message) -> bool {
        if let Some(header) = &message.header {
            let num_required_signatures = header.num_required_signatures as usize;
            let num_readonly_signed_accounts = header.num_readonly_signed_accounts as usize;
            let num_readonly_unsigned_accounts = header.num_readonly_unsigned_accounts as usize;

            // Solana账户排序：
            // 1. 需要签名的可写账户 (0 to num_required_signatures - num_readonly_signed_accounts - 1)
            // 2. 需要签名的只读账户 (num_required_signatures - num_readonly_signed_accounts to num_required_signatures - 1)
            // 3. 不需要签名的可写账户 (num_required_signatures to account_keys.len() - num_readonly_unsigned_accounts - 1)
            // 4. 不需要签名的只读账户 (account_keys.len() - num_readonly_unsigned_accounts to account_keys.len() - 1)

            if account_index < num_required_signatures {
                // 需要签名的账户
                account_index < (num_required_signatures - num_readonly_signed_accounts)
            } else {
                // 不需要签名的账户
                let unsigned_start = num_required_signatures;
                let readonly_unsigned_start =
                    message.account_keys.len() - num_readonly_unsigned_accounts;
                account_index >= unsigned_start && account_index < readonly_unsigned_start
            }
        } else {
            // 如果没有header信息，无法判断，默认认为都可写（保守处理）
            true
        }
    }

    /// 获取指定签名的Solana交易详情。
    ///
    /// # 参数
    /// - `signature`: 交易签名（哈希）。
    ///
    /// # 返回
    /// `Result`，包含`Transaction`结构体或错误信息。
    pub async fn get_transaction(
        &self,
        signature: &str,
    ) -> Result<Transaction, Box<dyn std::error::Error>> {
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

        let response = self
            .client
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

    /// 获取目标交易周围的交易（前4笔和后4笔交易，包含所有类型）
    ///
    /// # 参数
    /// - `target_signature`: 目标交易签名
    ///
    /// # 返回
    /// `Result`，包含目标交易及其周围交易的向量和目标交易在结果中的索引
    pub async fn get_nearby_transactions(
        &self,
        target_signature: &str,
    ) -> Result<(Vec<Transaction>, usize), Box<dyn std::error::Error>> {
        // 首先获取目标交易信息
        let target_tx = self.get_transaction(target_signature).await?;
        let slot = target_tx.slot;

        // 获取完整区块
        let all_transactions = self.get_full_block(slot).await?;

        // 找到目标交易在区块中的索引
        let target_index = all_transactions
            .iter()
            .position(|tx| tx.signature == target_signature)
            .ok_or("无法在区块中找到目标交易")?;

        // 收集前4笔交易（包含所有类型）
        let start_index = if target_index >= 4 {
            target_index - 4
        } else {
            0
        };
        let prev_txs = all_transactions[start_index..target_index].to_vec();

        // 收集后4笔交易（包含所有类型）
        let end_index = (target_index + 5).min(all_transactions.len());
        let next_txs = all_transactions[(target_index + 1)..end_index].to_vec();

        // 组合所有交易：前4笔 + 目标交易 + 后4笔
        let mut nearby_transactions = Vec::new();
        nearby_transactions.extend(prev_txs);
        let target_index_in_result = nearby_transactions.len(); // 目标交易在结果中的索引
        nearby_transactions.push(target_tx);
        nearby_transactions.extend(next_txs);

        log::info!(
            "获取到 {} 笔前置交易，{} 笔后置交易（包含所有类型交易）",
            target_index_in_result,
            nearby_transactions.len() - target_index_in_result - 1
        );

        Ok((nearby_transactions, target_index_in_result))
    }

    /// 检查交易是否为投票交易
    fn is_vote_transaction(&self, tx: &Transaction) -> bool {
        // 检查账户列表中是否包含投票程序账户
        const VOTE_PROGRAM_ID: &str = "Vote111111111111111111111111111111111111111";
        const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";

        let has_vote_account = tx
            .transaction
            .message
            .account_keys
            .iter()
            .any(|account| account == VOTE_PROGRAM_ID || account == STAKE_PROGRAM_ID);

        if has_vote_account {
            return true;
        }

        // 检查程序ID（作为备用检测）
        tx.transaction.message.instructions.iter().any(|inst| {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(inst.program_id_index as usize)
            {
                program_id == VOTE_PROGRAM_ID || program_id == STAKE_PROGRAM_ID
            } else {
                false
            }
        })
    }

    /// 获取指定区块的完整信息，包含所有交易详情。
    ///
    /// # 参数
    /// - `slot`: 区块号。
    ///
    /// # 返回
    /// `Result`，包含该区块所有交易的`Transaction`结构体向量或错误信息。
    pub async fn get_full_block(
        &self,
        slot: u64,
    ) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
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

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request_body)
            .send()
            .await?;
        let json: Value = response.json().await?;

        if let Some(result) = json.get("result") {
            let block_time: Option<i64> = result.get("blockTime").and_then(|v| v.as_i64());

            if let Some(txs_json) = result.get("transactions") {
                let mut transactions = Vec::new();
                if let Some(txs_array) = txs_json.as_array() {
                    for tx_json in txs_array {
                        if let Some(tx_data_json) = tx_json.get("transaction") {
                            if let Ok(tx_data) =
                                serde_json::from_value::<TransactionData>(tx_data_json.clone())
                            {
                                let signature =
                                    tx_data.signatures.first().cloned().unwrap_or_default();
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

    /// 获取交易的详细信息，包括余额变化
    pub async fn get_transaction_with_balance_changes(
        &self,
        signature: &str,
    ) -> Result<TransactionWithBalanceChanges, Box<dyn std::error::Error>> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "json",
                    "maxSupportedTransactionVersion": 0,
                    "commitment": "confirmed"
                }
            ]
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request_body)
            .timeout(Duration::from_secs(30))
            .send()
            .await?;

        let json: Value = response.json().await?;

        if let Some(result) = json.get("result") {
            if !result.is_null() {
                return Ok(serde_json::from_value(result.clone())?);
            }
        }

        Err(format!("Transaction not found: {}", signature).into())
    }
}

/// 账户余额变化信息
#[derive(Debug, Clone)]
pub struct AccountBalanceChange {
    pub account: String,
    pub pre_balance: u64,
    pub post_balance: u64,
    pub change: i64, // 可以为负数
}

/// Token余额变化信息
#[derive(Debug, Clone)]
pub struct TokenBalanceChange {
    pub account: String,
    pub mint: String,
    pub owner: String,
    pub pre_amount: u64,
    pub post_amount: u64,
    pub change: i64,
    pub decimals: u8,
    pub pre_amount_ui: f64,
    pub post_amount_ui: f64,
    pub change_ui: f64,
}

/// 包含余额变化的交易信息
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TransactionWithBalanceChanges {
    #[serde(flatten)]
    pub transaction: Transaction,
    pub meta: Option<TransactionMeta>,
}

/// 交易元数据，包含余额变化信息
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TransactionMeta {
    pub err: Option<Value>,
    pub fee: u64,
    #[serde(rename = "preBalances")]
    pub pre_balances: Vec<u64>,
    #[serde(rename = "postBalances")]
    pub post_balances: Vec<u64>,
    #[serde(rename = "preTokenBalances", default)]
    pub pre_token_balances: Vec<TokenBalance>,
    #[serde(rename = "postTokenBalances", default)]
    pub post_token_balances: Vec<TokenBalance>,
}

/// Token余额信息
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenBalance {
    #[serde(rename = "accountIndex")]
    pub account_index: usize,
    pub mint: String,
    pub owner: Option<String>,
    #[serde(rename = "uiTokenAmount")]
    pub ui_token_amount: UiTokenAmount,
}

/// UI格式的Token金额
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UiTokenAmount {
    pub amount: String,
    pub decimals: u8,
    #[serde(rename = "uiAmount")]
    pub ui_amount: Option<f64>,
    #[serde(rename = "uiAmountString")]
    pub ui_amount_string: String,
}
