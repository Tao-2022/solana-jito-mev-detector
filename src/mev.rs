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

/// 交易价值分析结果
#[derive(Debug, Clone)]
pub struct TradeValue {
    pub estimated_total_value: u64,
}

/// 池子信息结构体
#[derive(Debug, Clone)]
pub struct PoolInfo {
    pub dex_type: DexType,
    pub token_a: String,
    pub token_b: String,
    pub decimals_a: u8,
    pub decimals_b: u8,
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

/// 攻击者利润详情
#[derive(Debug, Clone)]
pub struct AttackerProfit {
    pub token_a_profit: i64,
    pub token_b_profit: i64,
    pub net_sol_profit: u64,
    pub confidence: f64,
}

/// 账户资金流入分析结果
#[derive(Debug, Clone)]
pub struct AccountInflowAnalysis {
    pub total_sol_inflow: u64,
    pub token_inflows: Vec<TokenFlowDetail>,
    pub involved_addresses: HashSet<String>,
    pub instruction_count: usize,
}

/// 账户资金流出分析结果
#[derive(Debug, Clone)]
pub struct AccountOutflowAnalysis {
    pub total_sol_outflow: u64,
    pub involved_addresses: HashSet<String>,
    pub instruction_count: usize,
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

/// 系统转账流入信息
#[derive(Debug, Clone)]
struct SystemTransferInflow {
    amount: u64,
    from_address: String,
}

/// 综合交易流动分析结果
#[derive(Debug, Clone)]
pub struct ComprehensiveFlowAnalysis {
    pub net_sol_amount: u64,
    pub token_flows: Vec<TokenFlowDetail>,
    pub total_instructions: usize,
    pub dex_complexity_score: f64,
    pub involved_addresses: HashSet<String>,
}

/// 系统转账流出信息
#[derive(Debug, Clone)]
struct SystemTransferOutflow {
    amount: u64,
    to_address: String,
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

        let has_multiple_accounts = account_count >= self.config.trade_size.min_swap_accounts;

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


    
    
    /// 解析代币转账金额
    fn parse_token_transfer_amount(&self, instruction_data: &str) -> Option<u64> {
        if let Ok(data) = bs58::decode(instruction_data).into_vec() {
            if data.len() >= 9 && data[0] == 3 { // SPL Token Transfer instruction
                if let Ok(amount_bytes) = data[1..9].try_into() {
                    return Some(u64::from_le_bytes(amount_bytes));
                }
            }
        }
        None
    }
    /// 计算交易向指定账户的资金流入量
    fn calculate_account_inflow(&self, tx: &Transaction, target_accounts: &[String]) -> AccountInflowAnalysis {
        let mut total_sol_inflow = 0u64;
        let mut token_inflows = Vec::new();
        let mut involved_addresses = HashSet::new();
        
        debug!("开始分析资金流入到目标账户:");
        debug!("目标账户: {:?}", target_accounts);
        
        for (i, instruction) in tx.transaction.message.instructions.iter().enumerate() {
            if let Some(program_id) = tx.transaction.message.account_keys.get(instruction.program_id_index as usize) {
                debug!("分析指令{}: {}", i + 1, program_id);
                
                match program_id.as_str() {
                    SYSTEM => {
                        if let Some(inflow) = self.analyze_system_transfer_inflow(instruction, &tx.transaction.message.account_keys, target_accounts) {
                            debug!("  发现System转账流入: {:.9} SOL, 来源: {}", inflow.amount as f64 / 1_000_000_000.0, inflow.from_address);
                            total_sol_inflow += inflow.amount;
                            involved_addresses.insert(inflow.from_address.clone());
                        }
                    },
                    TOKEN_PROGRAM_ID => {
                        if let Some(token_inflow) = self.analyze_token_transfer_inflow(instruction, &tx.transaction.message.account_keys, target_accounts) {
                            debug!("  发现Token转账流入: {:.9} {}", token_inflow.amount_ui, token_inflow.token_symbol);
                            if token_inflow.token_address == WSOL {
                                total_sol_inflow += token_inflow.amount;
                            } else {
                                token_inflows.push(token_inflow);
                            }
                        }
                    },
                    _ => {
                        if let Some(dex_inflow) = self.analyze_dex_program_inflow(instruction, &tx.transaction.message.account_keys, target_accounts, program_id) {
                            debug!("  DEX程序估算流入: {:.9} SOL", dex_inflow as f64 / 1_000_000_000.0);
                            total_sol_inflow += dex_inflow;
                        }
                    }
                }
            }
        }
        
        debug!("资金流入分析完成 - 总SOL流入: {:.9} SOL, 代币流入种类: {}", 
               total_sol_inflow as f64 / 1_000_000_000.0, token_inflows.len());
        
        AccountInflowAnalysis {
            total_sol_inflow,
            token_inflows,
            involved_addresses,
            instruction_count: tx.transaction.message.instructions.len(),
        }
    }
    
        /// 计算交易从指定账户的资金流出量
    fn calculate_account_outflow(&self, tx: &Transaction, target_accounts: &[String]) -> AccountOutflowAnalysis {
        let mut total_sol_outflow = 0u64;
        let mut involved_addresses = HashSet::new();
        
        debug!("开始分析资金从目标账户流出:");
        debug!("目标账户: {:?}", target_accounts);
        
        for (i, instruction) in tx.transaction.message.instructions.iter().enumerate() {
            if let Some(program_id) = tx.transaction.message.account_keys.get(instruction.program_id_index as usize) {
                debug!("分析指令{}: {}", i + 1, program_id);
                
                match program_id.as_str() {
                    SYSTEM => {
                        if let Some(outflow) = self.analyze_system_transfer_outflow(instruction, &tx.transaction.message.account_keys, target_accounts) {
                            debug!("  发现System转账流出: {:.9} SOL, 目标: {}", outflow.amount as f64 / 1_000_000_000.0, outflow.to_address);
                            total_sol_outflow += outflow.amount;
                            involved_addresses.insert(outflow.to_address.clone());
                        }
                    },
                    TOKEN_PROGRAM_ID => {
                        if let Some(token_outflow) = self.analyze_token_transfer_outflow(instruction, &tx.transaction.message.account_keys, target_accounts) {
                            debug!("  发现Token转账流出: {:.9} {}", token_outflow.amount_ui, token_outflow.token_symbol);
                            if token_outflow.token_address == WSOL {
                                total_sol_outflow += token_outflow.amount;
                            }
                        }
                    },
                    _ => {
                        if let Some(dex_outflow) = self.analyze_dex_program_outflow(instruction, &tx.transaction.message.account_keys, target_accounts, program_id) {
                            debug!("  DEX程序估算流出: {:.9} SOL", dex_outflow as f64 / 1_000_000_000.0);
                            total_sol_outflow += dex_outflow;
                        }
                    }
                }
            }
        }
        
        debug!("资金流出分析完成 - 总SOL流出: {:.9} SOL", total_sol_outflow as f64 / 1_000_000_000.0);
        
        AccountOutflowAnalysis {
            total_sol_outflow,
            involved_addresses,
            instruction_count: tx.transaction.message.instructions.len(),
        }
    }

    fn analyze_system_transfer_inflow(
        &self,
        instruction: &crate::client::Instruction,
        account_keys: &[String],
        target_accounts: &[String],
    ) -> Option<SystemTransferInflow> {
        if instruction.accounts.len() < 2 {
            return None;
        }
        
        let from_account = account_keys.get(instruction.accounts[0] as usize)?;
        let to_account = account_keys.get(instruction.accounts[1] as usize)?;
        
        if target_accounts.contains(to_account) {
            if let Some(amount) = self.parse_transfer_amount(&instruction.data) {
                return Some(SystemTransferInflow {
                    amount,
                    from_address: from_account.clone(),
                });
            }
        }
        
        None
    }
    
    /// 分析系统程序转账的流出情况
    fn analyze_system_transfer_outflow(
        &self,
        instruction: &crate::client::Instruction,
        account_keys: &[String],
        target_accounts: &[String],
    ) -> Option<SystemTransferOutflow> {
        if instruction.accounts.len() < 2 {
            return None;
        }
        
        let from_account = account_keys.get(instruction.accounts[0] as usize)?;
        let to_account = account_keys.get(instruction.accounts[1] as usize)?;
        
        if target_accounts.contains(from_account) {
            if let Some(amount) = self.parse_transfer_amount(&instruction.data) {
                return Some(SystemTransferOutflow {
                    amount,
                    to_address: to_account.clone(),
                });
            }
        }
        
        None
    }
    
    /// 分析SPL Token转账的流入情况
    fn analyze_token_transfer_inflow(
        &self,
        instruction: &crate::client::Instruction,
        account_keys: &[String],
        target_accounts: &[String],
    ) -> Option<TokenFlowDetail> {
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            if data.len() >= 9 && data[0] == 3 {
                if let Ok(amount_bytes) = data[1..9].try_into() {
                    let amount = u64::from_le_bytes(amount_bytes);
                    
                    if instruction.accounts.len() >= 3 {
                        let _source_account = account_keys.get(instruction.accounts[0] as usize)?;
                        let dest_account = account_keys.get(instruction.accounts[1] as usize)?;
                        
                        if target_accounts.contains(dest_account) {
                            let token_address = self.infer_token_mint_from_accounts(account_keys).unwrap_or_else(|| WSOL.to_string());
                            
                            return Some(TokenFlowDetail {
                                token_address: token_address.clone(),
                                token_symbol: get_token_symbol(&token_address).to_string(),
                                amount,
                                amount_ui: self.convert_token_amount_to_ui(amount, get_token_decimals(&token_address)),
                                decimals: get_token_decimals(&token_address),
                            });
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// 分析SPL Token转账的流出情况
    fn analyze_token_transfer_outflow(
        &self,
        instruction: &crate::client::Instruction,
        account_keys: &[String],
        target_accounts: &[String],
    ) -> Option<TokenFlowDetail> {
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            if data.len() >= 9 && data[0] == 3 {
                if let Ok(amount_bytes) = data[1..9].try_into() {
                    let amount = u64::from_le_bytes(amount_bytes);
                    
                    if instruction.accounts.len() >= 3 {
                        let source_account = account_keys.get(instruction.accounts[0] as usize)?;
                        let _dest_account = account_keys.get(instruction.accounts[1] as usize)?;
                        
                        if target_accounts.contains(source_account) {
                            let token_address = self.infer_token_mint_from_accounts(account_keys).unwrap_or_else(|| WSOL.to_string());
                            
                            return Some(TokenFlowDetail {
                                token_address: token_address.clone(),
                                token_symbol: get_token_symbol(&token_address).to_string(),
                                amount,
                                amount_ui: self.convert_token_amount_to_ui(amount, get_token_decimals(&token_address)),
                                decimals: get_token_decimals(&token_address),
                            });
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// 分析DEX程序的资金流入（简化实现）
    fn analyze_dex_program_inflow(
        &self,
        instruction: &crate::client::Instruction,
        _account_keys: &[String],
        _target_accounts: &[String],
        program_id: &str,
    ) -> Option<u64> {
        let complexity_factor = match program_id {
            RAYDIUM_AMM | RAYDIUM_CLMM => 2.0,
            ORCA_WHIRLPOOLS | ORCA_V1 => 1.8,
            JUPITER => 1.5,
            _ => 1.0,
        };
        
        let base_estimation = instruction.accounts.len() as u64 * 1_000_000;
        Some((base_estimation as f64 * complexity_factor) as u64)
    }
    
    /// 分析DEX程序的资金流出（简化实现）
    fn analyze_dex_program_outflow(
        &self,
        instruction: &crate::client::Instruction,
        account_keys: &[String],
        target_accounts: &[String],
        program_id: &str,
    ) -> Option<u64> {
        self.analyze_dex_program_inflow(instruction, account_keys, target_accounts, program_id)
    }
    
    /// 从账户列表中推断代币mint地址
    fn infer_token_mint_from_accounts(&self, account_keys: &[String]) -> Option<String> {
        let common_tokens = [WSOL, USDC, USDT, RAY, BONK, WIF];
        for account in account_keys {
            if common_tokens.contains(&account.as_str()) {
                return Some(account.clone());
            }
        }
        
        None
    }
    
    /// 基于复杂度估算损失（当无法直接计算攻击者利润时）
    fn estimate_loss_from_complexity(
        &self,
        front_inflow: &AccountInflowAnalysis,
        back_outflow: &AccountOutflowAnalysis,
        user_trade_value: u64,
    ) -> u64 {
        let complexity_score = (front_inflow.instruction_count + back_outflow.instruction_count) as u64;
        let flow_volume = front_inflow.total_sol_inflow + back_outflow.total_sol_outflow;
        
        let base_loss_rate = 0.001 + (complexity_score as f64 / 20.0) * 0.004;
        let volume_factor = if flow_volume > 0 { (flow_volume as f64 / user_trade_value as f64).min(1.0) } else { 0.1 };
        
        let estimated_loss = (user_trade_value as f64 * base_loss_rate * volume_factor) as u64;
        estimated_loss.max(1_000_000)
    }
    
    /// 创建详细的代币损失信息
    fn create_detailed_token_losses(
        &self,
        front_inflow: &AccountInflowAnalysis,
        total_estimated_loss: u64,
    ) -> Vec<TokenLossDetail> {
        let mut losses = Vec::new();
        
        if total_estimated_loss > 0 {
            losses.push(TokenLossDetail {
                token_address: WSOL.to_string(),
                token_symbol: "SOL".to_string(),
                loss_amount: total_estimated_loss,
                loss_amount_ui: total_estimated_loss as f64 / 1_000_000_000.0,
            });
        }
        
        for token_inflow in &front_inflow.token_inflows {
            if token_inflow.token_address != WSOL {
                let token_loss = (token_inflow.amount as f64 * 0.02) as u64;
                if token_loss > 0 {
                    losses.push(TokenLossDetail {
                        token_address: token_inflow.token_address.clone(),
                        token_symbol: token_inflow.token_symbol.clone(),
                        loss_amount: token_loss,
                        loss_amount_ui: token_inflow.amount_ui * 0.02,
                    });
                }
            }
        }
        
        losses
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
        
        // 计算攻击者净利润
        let attacker_net_profit = back_outflow.total_sol_outflow.saturating_sub(front_inflow.total_sol_inflow);
        debug!("攻击者精确净利润: {:.9} SOL", attacker_net_profit as f64 / 1_000_000_000.0);
        
        // 基于真实数据计算用户损失
        let estimated_user_loss = if attacker_net_profit > 0 && user_trade_value > 0 {
            // 使用攻击者利润的85-95%作为用户损失的保守估计
            (attacker_net_profit as f64 * 0.90) as u64
        } else {
            // 如果无法从攻击者利润推算，使用交易价值的滑点估算
            (user_trade_value as f64 * 0.005) as u64 // 0.5%的滑点损失
        };
        
        let loss_percentage = if user_trade_value > 0 {
            (estimated_user_loss as f64 / user_trade_value as f64) * 100.0
        } else {
            0.0
        };
        
        // 创建详细的代币损失信息
        let token_losses = self.create_precise_token_losses(&front_inflow, estimated_user_loss);
        
        // 计算置信度（基于真实数据的置信度更高）
        let confidence_score = self.calculate_precise_confidence(
            &front_inflow, &back_outflow, attacker_net_profit, user_trade_value
        );
        
        // 验证结果
        let validation_passed = self.validate_precise_result(
            estimated_user_loss, attacker_net_profit, user_trade_value
        );
        
        // 识别主要损失代币
        let primary_loss_token = self.identify_primary_loss_token(&token_losses);
        
        if estimated_user_loss > 1000 { // 至少0.000001 SOL才认为有损失
            Some(UserLoss {
                estimated_loss_lamports: estimated_user_loss,
                loss_percentage: loss_percentage.min(15.0), // 最大损失15%
                calculation_method: "精确余额变化分析法".to_string(),
                mev_profit_lamports: attacker_net_profit,
                confidence_score,
                validation_passed,
                token_losses,
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
        for token_flow in &inflow.token_inflows {
            // 估算该Token的损失：使用Token流入量的1-3%作为损失估算
            let loss_rate = if token_flow.token_symbol == "USDC" || token_flow.token_symbol == "USDT" {
                0.02 // 稳定币损失率2%
            } else {
                0.015 // 其他Token损失率1.5%
            };
            
            let token_loss_ui = token_flow.amount_ui * loss_rate;
            let token_loss_amount = (token_flow.amount as f64 * loss_rate) as u64;
            
            if token_loss_ui > 0.001 { // 只记录大于0.001单位的损失
                losses.push(TokenLossDetail {
                    token_address: token_flow.token_address.clone(),
                    token_symbol: token_flow.token_symbol.clone(),
                    loss_amount: token_loss_amount,
                    loss_amount_ui: token_loss_ui,
                });
                
                debug!("检测到{}损失: {:.6} {}", 
                       token_flow.token_symbol, token_loss_ui, token_flow.token_symbol);
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
    
    /// 计算交集账户损失的置信度
    fn calculate_intersection_loss_confidence(
        &self,
        front_inflow: &AccountInflowAnalysis,
        back_outflow: &AccountOutflowAnalysis,
        attacker_net_profit: u64,
        user_trade_value: u64,
    ) -> f64 {
        let mut confidence = 0.0;
        
        if front_inflow.total_sol_inflow > 0 && back_outflow.total_sol_outflow > 0 {
            confidence += 0.3;
        } else if front_inflow.total_sol_inflow > 0 || back_outflow.total_sol_outflow > 0 {
            confidence += 0.15;
        }
        
        if attacker_net_profit > 0 {
            let profit_ratio = attacker_net_profit as f64 / user_trade_value as f64;
            if profit_ratio >= 0.001 && profit_ratio <= 0.1 {
                confidence += 0.25;
            } else if profit_ratio > 0.0 {
                confidence += 0.15;
            }
        }
        
        let total_instructions = front_inflow.instruction_count + back_outflow.instruction_count;
        confidence += 0.2 * (total_instructions as f64 / 10.0).min(1.0);
        
        let address_overlap = front_inflow.involved_addresses.intersection(&back_outflow.involved_addresses).count();
        confidence += 0.15 * (address_overlap as f64 / 3.0).min(1.0);
        
        confidence += 0.1;
        
        confidence.min(1.0)
    }
    
    /// 验证交集账户损失结果的合理性
    fn validate_intersection_loss_result(
        &self,
        estimated_loss: u64,
        attacker_profit: u64,
        user_trade_value: u64,
    ) -> bool {
        if estimated_loss > user_trade_value / 6 {
            return false;
        }
        
        if attacker_profit > 0 && estimated_loss > attacker_profit * 3 / 2 {
            return false;
        }
        
        if estimated_loss < 100_000 {
            return false;
        }
        
        if estimated_loss > 100_000_000_000 {
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

    /// 将代币数量转换为UI显示格式
    fn convert_token_amount_to_ui(&self, amount: u64, decimals: u8) -> f64 {
        amount as f64 / 10_u64.pow(decimals as u32) as f64
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