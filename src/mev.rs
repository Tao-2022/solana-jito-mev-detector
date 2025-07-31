use crate::client::{Transaction, TransactionWithBalanceChanges, 
                    AccountBalanceChange, TokenBalanceChange, TransactionMeta, TokenBalance};
use crate::locale::{Language, Locale};
use crate::settings::MevDetectionConfig;
use bs58;
use log::{debug, info};
use std::collections::HashSet;

/// MEV检测器主结构体
pub struct MevDetector {
    pub config: MevDetectionConfig,
    locale: Locale,
}

/// 三明治攻击检测结果
#[derive(Debug, Clone)]
pub struct SandwichDetails {
    pub front_tx: String,
    pub back_tx: String,
    pub account_intersection: Vec<String>,
    pub user_loss: Option<UserLoss>,
}

/// 用户损失分析结果
#[derive(Debug, Clone)]
pub struct UserLoss {
    pub estimated_loss_lamports: u64,
    pub loss_percentage: f64,
    pub calculation_method: String,
    pub mev_profit_lamports: u64,
    pub mev_profit_token: Option<String>, // 攻击者主要利润的token
    pub mev_profit_amount: f64, // 攻击者主要利润的数量
    pub confidence_score: f64,
    pub validation_passed: bool,
    pub token_losses: Vec<TokenLossDetail>,
    pub primary_loss_token: Option<String>,
}

/// 代币损失详情
#[derive(Debug, Clone)]
pub struct TokenLossDetail {
    pub token_address: String,
    pub token_symbol: String,
    pub loss_amount: u64,
    pub loss_amount_ui: f64,
}


/// DEX类型枚举
#[derive(Debug, Clone, PartialEq)]
pub enum DexType {
    Raydium,
    Orca,
    Jupiter, 
    PumpFun,
    Serum,
    Unknown,
}


/// 代币流动详情
#[derive(Debug, Clone)]
pub struct TokenFlowDetail {
    pub token_address: String,
    pub token_symbol: String,
    pub amount: u64,
    pub amount_ui: f64,
    pub decimals: u8,
}

/// Swap指令解析结果
#[derive(Debug, Clone)]
pub struct SwapInstructionData {
    pub dex_type: DexType,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: u64,
    pub amount_out: u64,
    pub user_address: String,
    pub pool_address: String,
}

/// 交易指令解析汇总
#[derive(Debug, Clone)]
pub struct TransactionInstructionData {
    pub swap_instructions: Vec<SwapInstructionData>,
    pub total_sol_amount: u64,
    pub involved_tokens: Vec<String>,
}


/// 抢跑攻击检测结果
#[derive(Debug, Clone)]
pub struct FrontrunDetails {
    pub front_tx: String,
    pub account_intersection: Vec<String>,
}

// 程序ID常量定义
mod program_ids {
    pub const RAYDIUM_AMM: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
    pub const RAYDIUM_CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUQzGdR1qJRXgKhpNzc";
    pub const ORCA_WHIRLPOOLS: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
    pub const ORCA_V1: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    pub const SERUM_DEX: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
    pub const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    pub const PUMP_FUN: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";

    pub const SYSTEM: &str = "11111111111111111111111111111111";
    pub const MEMO: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDgQdddcxFr";
    pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
}

// 常用代币地址和信息
mod token_info {
    pub const WSOL: &str = "So11111111111111111111111111111111111111112";
    pub const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    pub const USDT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
    pub const RAY: &str = "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R";
    pub const BONK: &str = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
    pub const WIF: &str = "EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm";
    
    pub fn get_token_symbol(address: &str) -> &'static str {
        match address {
            WSOL => "WSOL",
            USDC => "USDC", 
            USDT => "USDT",
            RAY => "RAY",
            BONK => "BONK",
            WIF => "WIF",
            _ => "UNKNOWN",
        }
    }
    
    pub fn get_token_decimals(address: &str) -> u8 {
        match address {
            WSOL => 9,
            USDC => 6,
            USDT => 6,
            RAY => 6,
            BONK => 5,
            WIF => 6,
            _ => 9,
        }
    }
}

use program_ids::*;
use token_info::*;

// Jito 小费账户列表
const JITO_TIP_ACCOUNTS: [&str; 8] = [
    "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5",
    "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe",
    "Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY",
    "ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iAVflbD",
    "DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh",
    "ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt",
    "DttWaMuVvTiduZRnguLF7jNxG3tMK1dpv2vZeDbemFDF",
    "GGcvCardiohRDPcsyTuyNzTTBEsszS6b6X9dCg12N66X",
];

const ALLOWED_PROGRAMS_FOR_SIMPLE_TRANSFER: [&str; 2] = [SYSTEM, MEMO];

impl MevDetector {
    /// 创建新的MEV检测器实例
    pub fn new(config: MevDetectionConfig, language: Language) -> Self {
        Self { config, locale: Locale::new(language) }
    }

    /// 检查交易是否为简单的转账
    pub fn is_simple_transfer(&self, tx: &Transaction) -> bool {
        tx.transaction.message.instructions.iter().all(|inst| {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(inst.program_id_index as usize)
            {
                ALLOWED_PROGRAMS_FOR_SIMPLE_TRANSFER.contains(&program_id.as_str())
            } else {
                false
            }
        })
    }

    /// 检查目标交易前后交易中是否有Jito小费地址
    pub fn check_jito_tip_in_nearby_transactions(
        &self,
        block_transactions: &[Transaction],
        target_index: usize,
    ) -> Option<(usize, String, u64, bool, Vec<Transaction>)> {
        // 先检查目标交易前面的交易
        for i in (0..target_index).rev() {
            let tx = &block_transactions[i];
            if let Some((tip_account, tip_amount)) = self.check_single_transaction_for_jito_tip(tx)
            {
                info!("{}", self.locale.jito_tip_found_before());
                let bundle_end = (i + 5).min(block_transactions.len());
                let bundle_transactions = block_transactions[i..bundle_end].to_vec();
                return Some((i, tip_account, tip_amount, true, bundle_transactions));
            }
        }

        // 再检查目标交易后面的交易
        for i in (target_index + 1)..block_transactions.len() {
            let tx = &block_transactions[i];
            if let Some((tip_account, tip_amount)) = self.check_single_transaction_for_jito_tip(tx)
            {
                info!("{}", self.locale.jito_tip_found_after());
                let bundle_start = i.saturating_sub(4);
                let bundle_transactions = block_transactions[bundle_start..=i].to_vec();
                return Some((i, tip_account, tip_amount, false, bundle_transactions));
            }
        }

        None
    }

    /// 检查单个交易是否包含Jito小费
    fn check_single_transaction_for_jito_tip(&self, tx: &Transaction) -> Option<(String, u64)> {
        let jito_tip_indices: Vec<(usize, String)> = tx
            .transaction
            .message
            .account_keys
            .iter()
            .enumerate()
            .filter(|(_, account)| JITO_TIP_ACCOUNTS.contains(&account.as_str()))
            .map(|(index, account)| {
                debug!("Found Jito tip account: {}", account);
                (index, account.clone())
            })
            .collect();

        if jito_tip_indices.is_empty() {
            return None;
        }

        for instruction in &tx.transaction.message.instructions {
            let program_id = tx
                .transaction
                .message
                .account_keys
                .get(instruction.program_id_index as usize)?;

            for &account_index in &instruction.accounts {
                for &(jito_index, ref jito_address) in &jito_tip_indices {
                    if account_index as usize == jito_index {
                        if program_id == SYSTEM {
                            if let Some(amount) = self.parse_transfer_amount(&instruction.data) {
                                debug!("{}: {}", self.locale.jito_tip_parsed(), amount);
                                return Some((jito_address.clone(), amount));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// 解析转账指令数据中的金额
    fn parse_transfer_amount(&self, instruction_data: &str) -> Option<u64> {
        let data = bs58::decode(instruction_data).into_vec().ok()?;

        let amount = match data.len() {
            12 if data.get(0..4)? == [2, 0, 0, 0] => {
                u64::from_le_bytes(data.get(4..12)?.try_into().ok()?)
            }
            8 => {
                u64::from_le_bytes(data.as_slice().try_into().ok()?)
            }
            len if len >= 12 => {
                u64::from_le_bytes(data.get(4..12)?.try_into().ok()?)
            }
            len if len >= 8 => u64::from_le_bytes(data.get(0..8)?.try_into().ok()?),
            _ => return None,
        };

        if amount > 0 {
            Some(amount)
        } else {
            None
        }
    }

    /// 检测交易列表中是否存在三明治攻击
    pub fn detect_sandwich_attack(
        &self,
        transactions: &[Transaction],
        target_signature: &str,
    ) -> Option<SandwichDetails> {
        let target_index = transactions
            .iter()
            .position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        if !self.is_dex_transaction(target_tx) {
            return None;
        }

        let target_accounts = self.extract_filtered_accounts(target_tx);
        if target_accounts.is_empty() {
            return None;
        }

        debug!("Target transaction filtered accounts: {}", target_accounts.len());

        let mut front_candidates = Vec::new();
        for i in 0..target_index.min(2) {
            let front_tx = &transactions[target_index.saturating_sub(i + 1)];
            if !self.is_dex_transaction(front_tx) {
                continue;
            }

            let front_accounts = self.extract_filtered_accounts(front_tx);
            let front_intersection: Vec<String> = target_accounts
                .intersection(&front_accounts)
                .cloned()
                .collect();

            if !front_intersection.is_empty() {
                front_candidates.push((front_tx, front_intersection));
            }
        }

        let mut back_candidates = Vec::new();
        for i in 0..2.min(transactions.len() - target_index - 1) {
            let back_tx = &transactions[target_index + i + 1];
            if !self.is_dex_transaction(back_tx) {
                continue;
            }

            let back_accounts = self.extract_filtered_accounts(back_tx);
            let back_intersection: Vec<String> = target_accounts
                .intersection(&back_accounts)
                .cloned()
                .collect();

            if !back_intersection.is_empty() {
                back_candidates.push((back_tx, back_intersection));
            }
        }

        for (front_tx, front_intersection) in &front_candidates {
            for (back_tx, back_intersection) in &back_candidates {
                let intersection_similarity =
                    self.calculate_intersection_similarity(front_intersection, back_intersection);

                if intersection_similarity >= self.config.similarity_threshold {
                    info!(
                        "{} {:.1}%",
                        self.locale.sandwich_pattern_detected(),
                        intersection_similarity * 100.0
                    );

                    let mut combined_intersection = front_intersection.clone();
                    for account in back_intersection {
                        if !combined_intersection.contains(account) {
                            combined_intersection.push(account.clone());
                        }
                    }

                    return Some(SandwichDetails {
                        front_tx: front_tx.signature.clone(),
                        back_tx: back_tx.signature.clone(),
                        account_intersection: combined_intersection,
                        user_loss: None, // 不再在此处计算用户损失，只在精确分析中计算
                    });
                }
            }
        }

        None
    }

    /// 检测交易列表中是否存在抢跑攻击
    pub fn detect_frontrun_attack(
        &self,
        transactions: &[Transaction],
        target_signature: &str,
    ) -> Option<FrontrunDetails> {
        let target_index = transactions
            .iter()
            .position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        if !self.is_dex_transaction(target_tx) {
            return None;
        }

        let target_accounts = self.extract_filtered_accounts(target_tx);
        if target_accounts.is_empty() {
            return None;
        }

        debug!(
            "Front-run detection - target transaction filtered accounts: {}",
            target_accounts.len()
        );

        for i in (0..target_index).rev() {
            let potential_frontrun = &transactions[i];

            if !self.is_dex_transaction(potential_frontrun) {
                continue;
            }

            let frontrun_accounts = self.extract_filtered_accounts(potential_frontrun);

            let intersection: Vec<String> = target_accounts
                .intersection(&frontrun_accounts)
                .cloned()
                .collect();

            if !intersection.is_empty() {
                info!("{} {}", self.locale.frontrun_pattern_detected(), intersection.len());

                return Some(FrontrunDetails {
                    front_tx: potential_frontrun.signature.clone(),
                    account_intersection: intersection,
                });
            }
        }

        None
    }

    /// 提取交易中的过滤后账户
    fn extract_filtered_accounts(&self, tx: &Transaction) -> HashSet<String> {
        let mut filtered_accounts = HashSet::new();

        for instruction in &tx.transaction.message.instructions {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(instruction.program_id_index as usize)
            {
                if program_id == SYSTEM {
                    if self.is_small_transfer_instruction(
                        instruction,
                        &tx.transaction.message.account_keys,
                    ) {
                        continue;
                    }
                }

                for &acc_index in &instruction.accounts {
                    if let Some(account) =
                        tx.transaction.message.account_keys.get(acc_index as usize)
                    {
                        if !self.is_account_writable(acc_index as usize, &tx.transaction.message) {
                            continue;
                        }

                        if JITO_TIP_ACCOUNTS.contains(&account.as_str()) {
                            continue;
                        }

                        filtered_accounts.insert(account.clone());
                    }
                }
            }
        }

        filtered_accounts.retain(|account| {
            account.len() <= 44 &&
            account.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c))
        });

        filtered_accounts
    }

    /// 判断指定索引的账户是否可写
    fn is_account_writable(&self, account_index: usize, message: &crate::client::Message) -> bool {
        if let Some(header) = &message.header {
            let num_required_signatures = header.num_required_signatures as usize;
            let num_readonly_signed_accounts = header.num_readonly_signed_accounts as usize;
            let num_readonly_unsigned_accounts = header.num_readonly_unsigned_accounts as usize;

            if account_index < num_required_signatures {
                account_index < (num_required_signatures - num_readonly_signed_accounts)
            } else {
                let unsigned_start = num_required_signatures;
                let readonly_unsigned_start =
                    message.account_keys.len() - num_readonly_unsigned_accounts;
                account_index >= unsigned_start && account_index < readonly_unsigned_start
            }
        } else {
            true
        }
    }

    /// 检查指令是否为小额转账
    fn is_small_transfer_instruction(
        &self,
        instruction: &crate::client::Instruction,
        account_keys: &[String],
    ) -> bool {
        if let Some(program_id) = account_keys.get(instruction.program_id_index as usize) {
            if program_id != SYSTEM {
                return false;
            }
        } else {
            return false;
        }

        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            let amount = if data.len() == 12 && data[0..4] == [2, 0, 0, 0] {
                u64::from_le_bytes(data[4..12].try_into().unwrap_or([0; 8]))
            } else if data.len() == 8 {
                u64::from_le_bytes(data.try_into().unwrap_or([0; 8]))
            } else if data.len() >= 12 {
                u64::from_le_bytes(data[4..12].try_into().unwrap_or([0; 8]))
            } else {
                0
            };

            amount > 0 && amount < self.config.small_transfer_threshold
        } else {
            false
        }
    }

    /// 计算两个账户交集的相似度
    fn calculate_intersection_similarity(&self, set1: &[String], set2: &[String]) -> f64 {
        if set1.is_empty() && set2.is_empty() {
            return 1.0;
        }

        if set1.is_empty() || set2.is_empty() {
            return 0.0;
        }

        let set1_hash: HashSet<&String> = set1.iter().collect();
        let set2_hash: HashSet<&String> = set2.iter().collect();

        let intersection_count = set1_hash.intersection(&set2_hash).count();
        let union_count = set1_hash.union(&set2_hash).count();

        if union_count == 0 {
            0.0
        } else {
            intersection_count as f64 / union_count as f64
        }
    }

    /// 检查交易是否为DEX交易
    fn is_dex_transaction(&self, tx: &Transaction) -> bool {
        const DEX_PROGRAMS: [&str; 7] = [
            RAYDIUM_AMM,
            RAYDIUM_CLMM,
            ORCA_WHIRLPOOLS,
            ORCA_V1,
            SERUM_DEX,
            JUPITER,
            PUMP_FUN,
        ];

        let has_known_dex = tx.transaction.message.instructions.iter().any(|inst| {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(inst.program_id_index as usize)
            {
                DEX_PROGRAMS.contains(&program_id.as_str())
            } else {
                false
            }
        });

        if has_known_dex {
            return true;
        }

        self.is_likely_swap_transaction(tx)
    }

    /// 通过账户特征判断是否可能是swap交易
    fn is_likely_swap_transaction(&self, tx: &Transaction) -> bool {
        let account_count = tx.transaction.message.account_keys.len();

        let has_multiple_accounts = account_count >= 6; // 默认最少6个账户的swap交易

        let has_non_system_instructions = tx.transaction.message.instructions.iter().any(|inst| {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(inst.program_id_index as usize)
            {
                program_id != SYSTEM && program_id != MEMO
            } else {
                false
            }
        });

        let has_token_accounts = self.has_token_account_patterns(tx);

        has_multiple_accounts && has_non_system_instructions && has_token_accounts
    }

    /// 检查是否有token账户的特征
    fn has_token_account_patterns(&self, tx: &Transaction) -> bool {
        let typical_token_account_count = tx
            .transaction
            .message
            .account_keys
            .iter()
            .filter(|key| key.len() == 44)
            .count();

        typical_token_account_count >= 4
    }


    
    
    /// 基于真实余额变化的精确损失计算（新方法）
    pub async fn calculate_precise_sandwich_loss(
        &self,
        client: &crate::client::SolanaClient,
        front_tx_sig: &str,
        target_tx_sig: &str,
        back_tx_sig: &str,
    ) -> Option<UserLoss> {
        debug!("开始尝试使用余额变化进行精确损失计算");
        
        // 尝试获取三个交易的详细余额变化信息
        let front_tx_result = client.get_transaction_with_balance_changes(front_tx_sig).await;
        let target_tx_result = client.get_transaction_with_balance_changes(target_tx_sig).await;
        let back_tx_result = client.get_transaction_with_balance_changes(back_tx_sig).await;
        
        // 检查是否所有交易都能获取到余额变化数据
        if let (Ok(front_tx), Ok(target_tx), Ok(back_tx)) = 
            (front_tx_result, target_tx_result, back_tx_result) {
            
            debug!("成功获取所有交易的余额变化数据，使用精确分析");
            return self.perform_precise_analysis(&front_tx, &target_tx, &back_tx);
        }
        
        debug!("无法获取完整的余额变化数据（可能是历史交易），回退到改进的估算方法");
        None
    }
    
    /// 执行精确的余额变化分析
    fn perform_precise_analysis(
        &self,
        front_tx: &TransactionWithBalanceChanges,
        target_tx: &TransactionWithBalanceChanges,
        back_tx: &TransactionWithBalanceChanges,
    ) -> Option<UserLoss> {
        // 分析前置交易的真实流入
        let front_inflow = self.analyze_precise_inflow(front_tx);
        debug!("前置交易精确分析 - SOL流入: {:.9} SOL, Token流入数量: {}", 
               front_inflow.total_sol_inflow as f64 / 1_000_000_000.0, 
               front_inflow.token_inflows.len());
        
        // 分析后置交易的真实流出  
        let back_outflow = self.analyze_precise_outflow(back_tx);
        debug!("后置交易精确分析 - SOL流出: {:.9} SOL", 
               back_outflow.total_sol_outflow as f64 / 1_000_000_000.0);
        
        // 分析用户交易的真实价值
        let user_trade_value = self.analyze_precise_trade_value(target_tx);
        debug!("用户交易精确价值: {:.9} SOL", user_trade_value as f64 / 1_000_000_000.0);
        
        // 计算攻击者净利润（多token支持）
        let attacker_sol_profit = back_outflow.total_sol_outflow.saturating_sub(front_inflow.total_sol_inflow);
        debug!("攻击者SOL净利润: {:.9} SOL", attacker_sol_profit as f64 / 1_000_000_000.0);
        
        // 计算攻击者在各种token上的净利润
        let mut attacker_token_profits = Vec::new();
        
        // 分析后置交易的token流出（攻击者卖出获得的token）
        let back_token_outflows = self.analyze_precise_token_outflow(back_tx);
        
        // 计算每种token的净利润
        for back_outflow in &back_token_outflows {
            // 找到对应的前置交易流入
            if let Some(front_inflow_token) = front_inflow.token_inflows.iter()
                .find(|t| t.token_address == back_outflow.token_address) {
                
                // 计算净利润：后置流出 - 前置流入
                if back_outflow.amount_ui > front_inflow_token.amount_ui {
                    let net_profit_ui = back_outflow.amount_ui - front_inflow_token.amount_ui;
                    let net_profit_amount = back_outflow.amount.saturating_sub(front_inflow_token.amount);
                    
                    attacker_token_profits.push(TokenFlowDetail {
                        token_address: back_outflow.token_address.clone(),
                        token_symbol: back_outflow.token_symbol.clone(),
                        amount: net_profit_amount,
                        amount_ui: net_profit_ui,
                        decimals: back_outflow.decimals,
                    });
                    
                    debug!("攻击者{}净利润: {:.6} {}", 
                           back_outflow.token_symbol, net_profit_ui, back_outflow.token_symbol);
                }
            }
        }
        
        // 确定主要利润token（最大利润的token）
        let primary_profit_token = if attacker_sol_profit > 1_000_000 { // SOL利润 > 0.001
            Some(("SOL".to_string(), attacker_sol_profit as f64 / 1_000_000_000.0))
        } else {
            attacker_token_profits.iter()
                .max_by(|a, b| a.amount_ui.partial_cmp(&b.amount_ui).unwrap_or(std::cmp::Ordering::Equal))
                .map(|token| (token.token_symbol.clone(), token.amount_ui))
        };
        
        if let Some((profit_token, profit_amount)) = &primary_profit_token {
            debug!("攻击者主要利润: {:.6} {}", profit_amount, profit_token);
        }
        
        // 创建详细的代币损失信息
        let token_losses = self.create_precise_token_losses(&front_inflow, 0); // 先不传SOL损失
        
        // 基于真实数据计算用户损失
        let (estimated_user_loss, loss_percentage) = if !token_losses.is_empty() {
            // 如果有token损失，以主要token损失为准
            let primary_token_loss = token_losses.iter()
                .max_by(|a, b| a.loss_amount.cmp(&b.loss_amount));
            
            if let Some(primary_loss) = primary_token_loss {
                // 如果主要损失不是SOL，则用该token的损失值
                if primary_loss.token_symbol != "SOL" {
                    // 对于非SOL token，损失以该token为单位，百分比基于该token的流入量
                    let token_inflow = front_inflow.token_inflows.iter()
                        .find(|t| t.token_address == primary_loss.token_address);
                    
                    let percentage = if let Some(inflow) = token_inflow {
                        if inflow.amount_ui > 0.0 {
                            (primary_loss.loss_amount_ui / inflow.amount_ui) * 100.0
                        } else {
                            0.0
                        }
                    } else {
                        // 默认基于攻击者利润估算的百分比
                        if user_trade_value > 0 {
                            let sol_loss = (attacker_sol_profit as f64 * 0.90) as u64;
                            (sol_loss as f64 / user_trade_value as f64) * 100.0
                        } else {
                            0.0
                        }
                    };
                    
                    (primary_loss.loss_amount, percentage)
                } else {
                    // 主要损失是SOL
                    let sol_loss = if attacker_sol_profit > 0 && user_trade_value > 0 {
                        (attacker_sol_profit as f64 * 0.90) as u64
                    } else {
                        (user_trade_value as f64 * 0.005) as u64
                    };
                    
                    let percentage = if user_trade_value > 0 {
                        (sol_loss as f64 / user_trade_value as f64) * 100.0
                    } else {
                        0.0
                    };
                    
                    (sol_loss, percentage)
                }
            } else {
                // 没有token损失，使用SOL损失
                let sol_loss = if attacker_sol_profit > 0 && user_trade_value > 0 {
                    (attacker_sol_profit as f64 * 0.90) as u64
                } else {
                    (user_trade_value as f64 * 0.005) as u64
                };
                
                let percentage = if user_trade_value > 0 {
                    (sol_loss as f64 / user_trade_value as f64) * 100.0
                } else {
                    0.0
                };
                
                (sol_loss, percentage)
            }
        } else {
            // 没有token损失，使用SOL损失
            let sol_loss = if attacker_sol_profit > 0 && user_trade_value > 0 {
                (attacker_sol_profit as f64 * 0.90) as u64
            } else {
                (user_trade_value as f64 * 0.005) as u64
            };
            
            let percentage = if user_trade_value > 0 {
                (sol_loss as f64 / user_trade_value as f64) * 100.0
            } else {
                0.0
            };
            
            (sol_loss, percentage)
        };
        
        // 如果主要损失是SOL，需要重新创建包含SOL损失的token_losses
        let final_token_losses = if token_losses.is_empty() || 
            token_losses.iter().all(|t| t.token_symbol != "SOL") {
            self.create_precise_token_losses(&front_inflow, estimated_user_loss)
        } else {
            token_losses
        };
        
        // 计算置信度（基于真实数据的置信度更高）
        let confidence_score = self.calculate_precise_confidence(
            &front_inflow, &back_outflow, attacker_sol_profit, user_trade_value
        );
        
        // 验证结果
        let validation_passed = self.validate_precise_result(
            estimated_user_loss, attacker_sol_profit, user_trade_value
        );
        
        // 识别主要损失代币
        let primary_loss_token = self.identify_primary_loss_token(&final_token_losses);
        
        if estimated_user_loss > 1000 { // 至少0.000001 SOL才认为有损失
            let (profit_token, profit_amount) = primary_profit_token.unwrap_or(("SOL".to_string(), attacker_sol_profit as f64 / 1_000_000_000.0));
            
            Some(UserLoss {
                estimated_loss_lamports: estimated_user_loss,
                loss_percentage: loss_percentage.min(15.0), // 最大损失15%
                calculation_method: "精确余额变化分析法".to_string(),
                mev_profit_lamports: attacker_sol_profit, // 保持SOL单位，用于兼容
                mev_profit_token: Some(profit_token),
                mev_profit_amount: profit_amount,
                confidence_score,
                validation_passed,
                token_losses: final_token_losses,
                primary_loss_token,
            })
        } else {
            None
        }
    }
    
    /// 分析交易的精确流入（基于余额变化）
    fn analyze_precise_inflow(&self, tx: &TransactionWithBalanceChanges) -> PreciseInflowAnalysis {
        let mut total_sol_inflow = 0u64;
        let mut token_inflows = Vec::new();
        
        if let Some(meta) = &tx.meta {
            // 分析SOL余额变化
            for (i, (&pre_balance, &post_balance)) in meta.pre_balances.iter()
                .zip(meta.post_balances.iter()).enumerate() {
                
                if post_balance > pre_balance {
                    let inflow = post_balance - pre_balance;
                    total_sol_inflow += inflow;
                    debug!("账户{}SOL流入: {:.9} SOL", 
                           i, inflow as f64 / 1_000_000_000.0);
                }
            }
            
            // 分析Token余额变化
            for post_token in &meta.post_token_balances {
                if let Some(pre_token) = meta.pre_token_balances.iter()
                    .find(|pre| pre.account_index == post_token.account_index && pre.mint == post_token.mint) {
                    
                    let pre_amount = pre_token.ui_token_amount.amount.parse::<u64>().unwrap_or(0);
                    let post_amount = post_token.ui_token_amount.amount.parse::<u64>().unwrap_or(0);
                    
                    if post_amount > pre_amount {
                        let inflow_amount = post_amount - pre_amount;
                        let ui_inflow = post_token.ui_token_amount.ui_amount.unwrap_or(0.0) -
                                       pre_token.ui_token_amount.ui_amount.unwrap_or(0.0);
                        
                        token_inflows.push(TokenFlowDetail {
                            token_address: post_token.mint.clone(),
                            token_symbol: get_token_symbol(&post_token.mint).to_string(),
                            amount: inflow_amount,
                            amount_ui: ui_inflow.abs(),
                            decimals: post_token.ui_token_amount.decimals,
                        });
                        
                        debug!("Token {}流入: {:.6} {}", 
                               post_token.mint, ui_inflow, get_token_symbol(&post_token.mint));
                    }
                }
            }
        }
        
        PreciseInflowAnalysis {
            total_sol_inflow,
            token_inflows,
        }
    }
    
    /// 分析交易的精确流出（基于余额变化）
    fn analyze_precise_outflow(&self, tx: &TransactionWithBalanceChanges) -> PreciseOutflowAnalysis {
        let mut total_sol_outflow = 0u64;
        
        if let Some(meta) = &tx.meta {
            // 分析SOL余额变化
            for (i, (&pre_balance, &post_balance)) in meta.pre_balances.iter()
                .zip(meta.post_balances.iter()).enumerate() {
                
                if pre_balance > post_balance {
                    let outflow = pre_balance - post_balance;
                    total_sol_outflow += outflow;
                    debug!("账户{}SOL流出: {:.9} SOL", 
                           i, outflow as f64 / 1_000_000_000.0);
                }
            }
        }
        
        PreciseOutflowAnalysis {
            total_sol_outflow,
        }
    }
    
    /// 分析交易的精确token流出（基于余额变化）
    fn analyze_precise_token_outflow(&self, tx: &TransactionWithBalanceChanges) -> Vec<TokenFlowDetail> {
        let mut token_outflows = Vec::new();
        
        if let Some(meta) = &tx.meta {
            // 分析Token余额变化
            for pre_token in &meta.pre_token_balances {
                if let Some(post_token) = meta.post_token_balances.iter()
                    .find(|post| post.account_index == pre_token.account_index && post.mint == pre_token.mint) {
                    
                    let pre_amount = pre_token.ui_token_amount.amount.parse::<u64>().unwrap_or(0);
                    let post_amount = post_token.ui_token_amount.amount.parse::<u64>().unwrap_or(0);
                    
                    // 检查是否有token流出（余额减少）
                    if pre_amount > post_amount {
                        let outflow_amount = pre_amount - post_amount;
                        let ui_outflow = pre_token.ui_token_amount.ui_amount.unwrap_or(0.0) -
                                        post_token.ui_token_amount.ui_amount.unwrap_or(0.0);
                        
                        token_outflows.push(TokenFlowDetail {
                            token_address: pre_token.mint.clone(),
                            token_symbol: get_token_symbol(&pre_token.mint).to_string(),
                            amount: outflow_amount,
                            amount_ui: ui_outflow.abs(),
                            decimals: pre_token.ui_token_amount.decimals,
                        });
                        
                        debug!("Token {}流出: {:.6} {}", 
                               pre_token.mint, ui_outflow, get_token_symbol(&pre_token.mint));
                    }
                }
            }
        }
        
        token_outflows
    }
    
    /// 分析交易的精确价值（基于余额变化）
    fn analyze_precise_trade_value(&self, tx: &TransactionWithBalanceChanges) -> u64 {
        let mut total_value = 0u64;
        
        if let Some(meta) = &tx.meta {
            // 统计所有SOL变化（进出）
            for (&pre_balance, &post_balance) in meta.pre_balances.iter()
                .zip(meta.post_balances.iter()) {
                
                let change = if post_balance > pre_balance {
                    post_balance - pre_balance
                } else {
                    pre_balance - post_balance
                };
                total_value += change;
            }
            
            // 对于swap交易，交易价值通常是SOL变化量的一半（买入的金额）
            total_value = total_value / 2;
        }
        
        total_value.max(1_000_000) // 最小0.001 SOL
    }
    
    /// 创建基于精确分析的代币损失详情
    fn create_precise_token_losses(&self, inflow: &PreciseInflowAnalysis, estimated_sol_loss: u64) -> Vec<TokenLossDetail> {
        let mut losses = Vec::new();
        
        // 添加SOL损失（如果有）
        if estimated_sol_loss > 0 {
            losses.push(TokenLossDetail {
                token_address: WSOL.to_string(),
                token_symbol: "SOL".to_string(),
                loss_amount: estimated_sol_loss,
                loss_amount_ui: estimated_sol_loss as f64 / 1_000_000_000.0,
            });
        }
        
        // 添加Token损失（基于前置交易中检测到的Token流入）
        // 排除SOL/WSOL，避免重复计算
        for token_flow in &inflow.token_inflows {
            // 跳过SOL和WSOL，避免重复计算
            if token_flow.token_address == WSOL || token_flow.token_symbol == "SOL" {
                continue;
            }
            
            // 基于用户实际损失和攻击者获得的token数量来计算更合理的损失
            // 对于大额token交易，使用更保守的损失率
            let loss_rate = if token_flow.amount_ui > 100000.0 { // 大额交易
                0.003 // 0.3%损失率，更保守
            } else if token_flow.token_symbol == "USDC" || token_flow.token_symbol == "USDT" {
                0.02 // 稳定币损失率2%
            } else {
                0.008 // 其他Token损失率0.8%，比之前更保守
            };
            
            let token_loss_ui = token_flow.amount_ui * loss_rate;
            let token_loss_amount = (token_flow.amount as f64 * loss_rate) as u64;
            
            // 提高最小损失阈值，过滤掉微小的损失
            if token_loss_ui > 1.0 { // 只记录大于1单位的损失
                losses.push(TokenLossDetail {
                    token_address: token_flow.token_address.clone(),
                    token_symbol: if token_flow.token_symbol == "UNKNOWN" {
                        // 尝试从地址中提取token名称或使用地址前8位作为标识
                        format!("Token_{}", &token_flow.token_address[0..8.min(token_flow.token_address.len())])
                    } else {
                        token_flow.token_symbol.clone()
                    },
                    loss_amount: token_loss_amount,
                    loss_amount_ui: token_loss_ui,
                });
                
                debug!("检测到{}损失: {:.6} {} (地址: {})", 
                       token_flow.token_symbol, token_loss_ui, token_flow.token_symbol, token_flow.token_address);
            }
        }
        
        losses
    }
    
    /// 计算基于精确数据的置信度
    fn calculate_precise_confidence(
        &self,
        _front_inflow: &PreciseInflowAnalysis,
        _back_outflow: &PreciseOutflowAnalysis, 
        attacker_profit: u64,
        user_trade_value: u64,
    ) -> f64 {
        let mut confidence: f64 = 0.7; // 基础置信度更高，因为使用了真实余额数据
        
        // 有明确的攻击者利润
        if attacker_profit > 1_000_000 { // > 0.001 SOL
            confidence += 0.2;
        }
        
        // 用户交易价值合理
        if user_trade_value > 100_000_000 && user_trade_value < 1_000_000_000_000 { // 0.1-1000 SOL
            confidence += 0.1;
        }
        
        confidence.min(0.95) // 最高95%置信度
    }
    
    /// 验证精确分析结果
    fn validate_precise_result(&self, user_loss: u64, attacker_profit: u64, user_trade_value: u64) -> bool {
        // 用户损失不应超过交易价值的20%
        if user_trade_value > 0 && (user_loss as f64 / user_trade_value as f64) > 0.20 {
            return false;
        }
        
        // 用户损失应该与攻击者利润相关
        if attacker_profit > 0 && user_loss > attacker_profit * 2 {
            return false;
        }
        
        true
    }
    
    /// 识别主要损失代币
    fn identify_primary_loss_token(&self, token_losses: &[TokenLossDetail]) -> Option<String> {
        token_losses.iter()
            .max_by(|a, b| a.loss_amount.cmp(&b.loss_amount))
            .map(|loss| loss.token_address.clone())
    }
    
}

/// 精确流入分析结果（基于余额变化）
#[derive(Debug, Clone)]
pub struct PreciseInflowAnalysis {
    pub total_sol_inflow: u64,
    pub token_inflows: Vec<TokenFlowDetail>,
}

/// 精确流出分析结果（基于余额变化）
#[derive(Debug, Clone)]
pub struct PreciseOutflowAnalysis {
    pub total_sol_outflow: u64,
}

impl MevDetector {
    /// 解析交易中的swap指令数据
    pub fn parse_transaction_instructions(&self, tx: &Transaction) -> TransactionInstructionData {
        let mut swap_instructions = Vec::new();
        let mut total_sol_amount = 0u64;
        let mut involved_tokens = Vec::new();
        
        debug!("开始解析交易指令，共{}个指令", tx.transaction.message.instructions.len());
        
        for (idx, instruction) in tx.transaction.message.instructions.iter().enumerate() {
            if let Some(program_id) = tx.transaction.message.account_keys.get(instruction.program_id_index as usize) {
                debug!("指令{}: program_id = {}", idx, program_id);
                
                if let Some(swap_data) = self.parse_swap_instruction(instruction, &tx.transaction.message.account_keys, program_id) {
                    debug!("成功解析swap指令: {:?}", swap_data);
                    total_sol_amount += swap_data.amount_in;
                    
                    if !involved_tokens.contains(&swap_data.token_in) {
                        involved_tokens.push(swap_data.token_in.clone());
                    }
                    if !involved_tokens.contains(&swap_data.token_out) {
                        involved_tokens.push(swap_data.token_out.clone());
                    }
                    
                    swap_instructions.push(swap_data);
                }
            }
        }
        
        debug!("指令解析完成，找到{}个swap指令", swap_instructions.len());
        
        TransactionInstructionData {
            swap_instructions,
            total_sol_amount,
            involved_tokens,
        }
    }
    
    /// 解析单个swap指令
    fn parse_swap_instruction(
        &self, 
        instruction: &crate::client::Instruction, 
        account_keys: &[String], 
        program_id: &str
    ) -> Option<SwapInstructionData> {
        match program_id {
            program_ids::RAYDIUM_AMM => self.parse_raydium_amm_swap(instruction, account_keys),
            program_ids::RAYDIUM_CLMM => self.parse_raydium_clmm_swap(instruction, account_keys),
            program_ids::ORCA_WHIRLPOOLS => self.parse_orca_whirlpool_swap(instruction, account_keys),
            program_ids::ORCA_V1 => self.parse_orca_v1_swap(instruction, account_keys),
            program_ids::JUPITER => self.parse_jupiter_swap(instruction, account_keys),
            program_ids::PUMP_FUN => self.parse_pump_fun_swap(instruction, account_keys),
            _ => {
                debug!("未知的DEX程序: {}", program_id);
                None
            }
        }
    }
    
    /// 解析Raydium AMM swap指令
    fn parse_raydium_amm_swap(
        &self, 
        instruction: &crate::client::Instruction, 
        account_keys: &[String]
    ) -> Option<SwapInstructionData> {
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            // Raydium AMM swap指令标识符通常是 [9] (swap指令)
            if data.len() >= 17 && data[0] == 9 {
                let amount_in = u64::from_le_bytes(data[1..9].try_into().ok()?);
                let amount_out = u64::from_le_bytes(data[9..17].try_into().ok()?);
                
                // 解析账户信息
                let user_address = account_keys.get(*instruction.accounts.get(16)? as usize)?.clone();
                let pool_address = account_keys.get(*instruction.accounts.get(1)? as usize)?.clone();
                
                // 推断token地址
                let token_in = self.infer_token_from_accounts(&instruction.accounts, account_keys, true)?;
                let token_out = self.infer_token_from_accounts(&instruction.accounts, account_keys, false)?;
                
                debug!("Raydium AMM swap: {} -> {}, amount_in: {}, amount_out: {}",
                       get_token_symbol(&token_in), get_token_symbol(&token_out), amount_in, amount_out);
                
                return Some(SwapInstructionData {
                    dex_type: DexType::Raydium,
                    token_in,
                    token_out,
                    amount_in,
                    amount_out,
                    user_address,
                    pool_address,
                });
            }
        }
        None
    }
    
    /// 解析Raydium CLMM swap指令
    fn parse_raydium_clmm_swap(
        &self, 
        instruction: &crate::client::Instruction, 
        account_keys: &[String]
    ) -> Option<SwapInstructionData> {
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            // CLMM swap指令可能有不同的标识符
            if data.len() >= 17 {
                // 尝试解析金额（位置可能不同）
                let amount_in = if data.len() >= 9 {
                    u64::from_le_bytes(data[1..9].try_into().ok()?)
                } else { 0 };
                
                let amount_out = if data.len() >= 17 {
                    u64::from_le_bytes(data[9..17].try_into().ok()?)
                } else { 0 };
                
                let user_address = account_keys.get(*instruction.accounts.get(0)? as usize)?.clone();
                let pool_address = account_keys.get(*instruction.accounts.get(1)? as usize)?.clone();
                
                let token_in = self.infer_token_from_accounts(&instruction.accounts, account_keys, true)?;
                let token_out = self.infer_token_from_accounts(&instruction.accounts, account_keys, false)?;
                
                debug!("Raydium CLMM swap: {} -> {}, amount_in: {}, amount_out: {}",
                       get_token_symbol(&token_in), get_token_symbol(&token_out), amount_in, amount_out);
                
                return Some(SwapInstructionData {
                    dex_type: DexType::Raydium,
                    token_in,
                    token_out,
                    amount_in,
                    amount_out,
                    user_address,
                    pool_address,
                });
            }
        }
        None
    }
    
    /// 解析Orca Whirlpool swap指令
    fn parse_orca_whirlpool_swap(
        &self, 
        instruction: &crate::client::Instruction, 
        account_keys: &[String]
    ) -> Option<SwapInstructionData> {
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            // Orca whirlpool swap 指令标识
            if data.len() >= 25 && data[0..8] == [0xf8, 0xc6, 0x9e, 0x91, 0xe1, 0x75, 0x87, 0xc8] {
                let amount_in = u64::from_le_bytes(data[8..16].try_into().ok()?);
                let amount_out = u64::from_le_bytes(data[16..24].try_into().ok()?);
                
                let user_address = account_keys.get(*instruction.accounts.get(0)? as usize)?.clone();
                let pool_address = account_keys.get(*instruction.accounts.get(1)? as usize)?.clone();
                
                let token_in = self.infer_token_from_accounts(&instruction.accounts, account_keys, true)?;
                let token_out = self.infer_token_from_accounts(&instruction.accounts, account_keys, false)?;
                
                debug!("Orca Whirlpool swap: {} -> {}, amount_in: {}, amount_out: {}",
                       get_token_symbol(&token_in), get_token_symbol(&token_out), amount_in, amount_out);
                
                return Some(SwapInstructionData {
                    dex_type: DexType::Orca,
                    token_in,
                    token_out,
                    amount_in,
                    amount_out,
                    user_address,
                    pool_address,
                });
            }
        }
        None
    }
    
    /// 解析Orca V1 swap指令
    fn parse_orca_v1_swap(
        &self, 
        instruction: &crate::client::Instruction, 
        account_keys: &[String]
    ) -> Option<SwapInstructionData> {
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            // Orca V1 swap指令
            if data.len() >= 17 && data[0] == 1 {
                let amount_in = u64::from_le_bytes(data[1..9].try_into().ok()?);
                let amount_out = u64::from_le_bytes(data[9..17].try_into().ok()?);
                
                let user_address = account_keys.get(*instruction.accounts.get(0)? as usize)?.clone();
                let pool_address = account_keys.get(*instruction.accounts.get(1)? as usize)?.clone();
                
                let token_in = self.infer_token_from_accounts(&instruction.accounts, account_keys, true)?;
                let token_out = self.infer_token_from_accounts(&instruction.accounts, account_keys, false)?;
                
                debug!("Orca V1 swap: {} -> {}, amount_in: {}, amount_out: {}",
                       get_token_symbol(&token_in), get_token_symbol(&token_out), amount_in, amount_out);
                
                return Some(SwapInstructionData {
                    dex_type: DexType::Orca,
                    token_in,
                    token_out,
                    amount_in,
                    amount_out,
                    user_address,
                    pool_address,
                });
            }
        }
        None
    }
    
    /// 解析Jupiter swap指令
    fn parse_jupiter_swap(
        &self, 
        instruction: &crate::client::Instruction, 
        account_keys: &[String]
    ) -> Option<SwapInstructionData> {
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            // Jupiter是聚合器，指令格式可能更复杂
            if data.len() >= 17 {
                // 尝试解析基本的swap信息
                let amount_in = if data.len() >= 9 {
                    u64::from_le_bytes(data[1..9].try_into().ok()?)
                } else { 0 };
                
                let user_address = account_keys.get(*instruction.accounts.get(0)? as usize)?.clone();
                let pool_address = account_keys.get(*instruction.accounts.get(1).unwrap_or(&0) as usize)?.clone();
                
                let token_in = self.infer_token_from_accounts(&instruction.accounts, account_keys, true)?;
                let token_out = self.infer_token_from_accounts(&instruction.accounts, account_keys, false)?;
                
                debug!("Jupiter swap: {} -> {}, amount_in: {}",
                       get_token_symbol(&token_in), get_token_symbol(&token_out), amount_in);
                
                return Some(SwapInstructionData {
                    dex_type: DexType::Jupiter,
                    token_in,
                    token_out,
                    amount_in,
                    amount_out: 0, // Jupiter可能不直接提供预期输出
                    user_address,
                    pool_address,
                });
            }
        }
        None
    }
    
    /// 解析Pump.fun swap指令
    fn parse_pump_fun_swap(
        &self, 
        instruction: &crate::client::Instruction, 
        account_keys: &[String]
    ) -> Option<SwapInstructionData> {
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            // Pump.fun的指令格式
            if data.len() >= 17 {
                let amount_in = u64::from_le_bytes(data[1..9].try_into().ok()?);
                let amount_out = u64::from_le_bytes(data[9..17].try_into().ok()?);
                
                let user_address = account_keys.get(*instruction.accounts.get(0)? as usize)?.clone();
                let pool_address = account_keys.get(*instruction.accounts.get(1)? as usize)?.clone();
                
                let token_in = self.infer_token_from_accounts(&instruction.accounts, account_keys, true)?;
                let token_out = self.infer_token_from_accounts(&instruction.accounts, account_keys, false)?;
                
                debug!("Pump.fun swap: {} -> {}, amount_in: {}, amount_out: {}",
                       get_token_symbol(&token_in), get_token_symbol(&token_out), amount_in, amount_out);
                
                return Some(SwapInstructionData {
                    dex_type: DexType::PumpFun,
                    token_in,
                    token_out,
                    amount_in,
                    amount_out,
                    user_address,
                    pool_address,
                });
            }
        }
        None
    }
    
    /// 从账户列表推断token地址
    fn infer_token_from_accounts(
        &self, 
        accounts: &[u8], 
        account_keys: &[String], 
        is_input: bool
    ) -> Option<String> {
        // 根据账户位置推断token
        // 通常input token在前面的位置，output token在后面
        let start_idx = if is_input { 2 } else { 4 };
        let end_idx = if is_input { 6 } else { 8 };
        
        for i in start_idx..end_idx.min(accounts.len()) {
            if let Some(account) = account_keys.get(accounts[i] as usize) {
                // 检查是否是已知的token地址
                if self.is_known_token(account) {
                    return Some(account.clone());
                }
            }
        }
        
        // 如果没找到已知token，返回第一个可能的token账户
        if let Some(account_idx) = accounts.get(start_idx) {
            account_keys.get(*account_idx as usize).cloned()
        } else {
            None
        }
    }
    
    /// 检查是否是已知的token
    fn is_known_token(&self, address: &str) -> bool {
        matches!(address, 
            WSOL | USDC | USDT | RAY | BONK | WIF |
            "11111111111111111111111111111111" | // System program
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" // Token program
        )
    }
    
    /// 基于指令解析数据计算更精确的损失
    pub async fn calculate_instruction_based_loss(
        &self,
        client: &crate::client::SolanaClient,
        front_tx_sig: &str,
        target_tx_sig: &str,
        back_tx_sig: &str,
    ) -> Option<UserLoss> {
        debug!("开始基于指令解析的损失计算");
        
        // 获取三个交易
        let front_tx = client.get_transaction(front_tx_sig).await.ok()?;
        let target_tx = client.get_transaction(target_tx_sig).await.ok()?;
        let back_tx = client.get_transaction(back_tx_sig).await.ok()?;
        
        // 解析每个交易的指令数据
        let front_data = self.parse_transaction_instructions(&front_tx);
        let target_data = self.parse_transaction_instructions(&target_tx);
        let back_data = self.parse_transaction_instructions(&back_tx);
        
        debug!("指令解析完成 - 前置:{}个swap, 目标:{}个swap, 后置:{}个swap",
               front_data.swap_instructions.len(),
               target_data.swap_instructions.len(), 
               back_data.swap_instructions.len());
        
        // 分析攻击者的套利行为
        let attacker_profit = self.calculate_attacker_arbitrage_profit(&front_data, &back_data);
        let user_trade_value = target_data.total_sol_amount;
        
        // 基于套利利润估算用户损失
        let estimated_loss = if attacker_profit > 0 {
            // 用户损失通常是攻击者利润的80-95%
            (attacker_profit as f64 * 0.85) as u64
        } else {
            // 如果无法计算攻击者利润，使用滑点估算
            (user_trade_value as f64 * 0.005) as u64
        };
        
        let loss_percentage = if user_trade_value > 0 {
            (estimated_loss as f64 / user_trade_value as f64) * 100.0
        } else {
            0.0
        };
        
        // 创建token损失详情
        let token_losses = self.create_instruction_based_token_losses(&target_data, estimated_loss);
        
        // 计算置信度
        let confidence_score = self.calculate_instruction_based_confidence(&front_data, &target_data, &back_data);
        
        // 验证结果
        let validation_passed = estimated_loss > 1000 && 
                               loss_percentage <= 20.0 && 
                               user_trade_value > 0;
        
        let primary_loss_token = self.identify_primary_loss_token(&token_losses);
        
        if validation_passed && estimated_loss > 1000 {
            Some(UserLoss {
                estimated_loss_lamports: estimated_loss,
                loss_percentage: loss_percentage.min(15.0),
                calculation_method: "指令解析分析法".to_string(),
                mev_profit_lamports: attacker_profit,
                mev_profit_token: Some("SOL".to_string()), // 指令解析暂时只支持SOL利润
                mev_profit_amount: attacker_profit as f64 / 1_000_000_000.0,
                confidence_score,
                validation_passed,
                token_losses,
                primary_loss_token,
            })
        } else {
            None
        }
    }
    
    /// 计算攻击者套利利润
    fn calculate_attacker_arbitrage_profit(
        &self, 
        front_data: &TransactionInstructionData, 
        back_data: &TransactionInstructionData
    ) -> u64 {
        // 简化计算：前置交易投入 - 后置交易获得
        let front_investment = front_data.total_sol_amount;
        let back_gains = back_data.total_sol_amount;
        
        if back_gains > front_investment {
            back_gains - front_investment
        } else {
            0
        }
    }
    
    /// 创建基于指令解析的token损失
    fn create_instruction_based_token_losses(
        &self, 
        target_data: &TransactionInstructionData, 
        estimated_sol_loss: u64
    ) -> Vec<TokenLossDetail> {
        let mut losses = Vec::new();
        
        // 添加SOL损失
        if estimated_sol_loss > 0 {
            losses.push(TokenLossDetail {
                token_address: WSOL.to_string(),
                token_symbol: "SOL".to_string(),
                loss_amount: estimated_sol_loss,
                loss_amount_ui: estimated_sol_loss as f64 / 1_000_000_000.0,
            });
        }
        
        // 基于swap指令添加其他token损失
        for swap in &target_data.swap_instructions {
            // 跳过SOL/WSOL，避免重复计算
            if swap.token_out == WSOL {
                continue;
            }
            
            let token_symbol = get_token_symbol(&swap.token_out);
            
            // 使用更保守的损失率，特别是对于大额交易
            let amount_out_ui = swap.amount_out as f64 / 1_000_000.0; // 假设6位小数
            let loss_rate = if amount_out_ui > 100000.0 { // 大额交易
                0.003 // 0.3%
            } else if token_symbol == "USDC" || token_symbol == "USDT" {
                0.02 // 2%
            } else {
                0.008 // 0.8%
            };
            
            let token_loss_ui = amount_out_ui * loss_rate;
            let token_loss = (swap.amount_out as f64 * loss_rate) as u64;
            
            // 只记录大于1单位的损失
            if token_loss_ui > 1.0 {
                losses.push(TokenLossDetail {
                    token_address: swap.token_out.clone(),
                    token_symbol: if token_symbol == "UNKNOWN" {
                        format!("Token_{}", &swap.token_out[0..8.min(swap.token_out.len())])
                    } else {
                        token_symbol.to_string()
                    },
                    loss_amount: token_loss,
                    loss_amount_ui: token_loss_ui,
                });
            }
        }
        
        losses
    }
    
    /// 计算基于指令解析的置信度
    fn calculate_instruction_based_confidence(
        &self,
        front_data: &TransactionInstructionData,
        _target_data: &TransactionInstructionData,
        back_data: &TransactionInstructionData,
    ) -> f64 {
        let mut confidence: f64 = 0.6; // 基础置信度
        
        // 有前置和后置交易的swap指令
        if !front_data.swap_instructions.is_empty() && !back_data.swap_instructions.is_empty() {
            confidence += 0.25;
        }
        
        // Token匹配度
        let common_tokens: HashSet<_> = front_data.involved_tokens.iter()
            .filter(|token| back_data.involved_tokens.contains(token))
            .collect();
        
        if !common_tokens.is_empty() {
            confidence += 0.15;
        }
        
        confidence.min(0.9) // 最高90%置信度（指令解析可能有误差）
    }
}