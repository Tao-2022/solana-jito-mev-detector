use crate::client::Transaction;
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
    pub confidence_score: f64, // 新增：置信度评分 (0.0-1.0)
    pub validation_passed: bool, // 新增：是否通过验证
}

/// 交易价值分析结果
#[derive(Debug, Clone)]
pub struct TradeValue {
    pub sol_amount: u64,
    pub instruction_complexity: u64,
    pub account_complexity: u64,
    pub estimated_total_value: u64,
    pub confidence: f64, // 估算置信度
}

/// 代币流动分析结果
#[derive(Debug, Clone)]
pub struct TokenFlow {
    pub net_sol_change: i64, // 净SOL变化（可为负）
    pub instruction_count: usize,
    pub writable_account_count: usize,
    pub estimated_token_value: u64,
}

/// 抢跑攻击检测结果
#[derive(Debug, Clone)]
pub struct FrontrunDetails {
    pub front_tx: String,
    pub victim_tx: String,
    pub account_intersection: Vec<String>,
}

// 程序ID常量定义
mod program_ids {
    // 主要 DEX 程序 ID
    pub const RAYDIUM_AMM: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
    pub const RAYDIUM_CLMM: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUQzGdR1qJRXgKhpNzc";
    pub const ORCA_WHIRLPOOLS: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
    pub const ORCA_V1: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    pub const SERUM_DEX: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
    pub const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    pub const PUMP_FUN: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";

    // 系统程序 ID
    pub const SYSTEM: &str = "11111111111111111111111111111111";
    pub const MEMO: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDgQdddcxFr";
}

use program_ids::*;

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

// 允许的简单转账程序
const ALLOWED_PROGRAMS_FOR_SIMPLE_TRANSFER: [&str; 2] = [SYSTEM, MEMO];

impl MevDetector {
    /// 创建新的MEV检测器实例
    pub fn new(config: MevDetectionConfig, language: Language) -> Self {
        Self { config, locale: Locale::new(language) }
    }

    /// 检查交易是否为简单的转账（仅涉及系统程序或Memo程序）
    ///
    /// # 参数
    /// * `tx` - 要检查的交易
    ///
    /// # 返回值
    /// 如果交易仅包含系统程序或Memo程序指令则返回true，否则返回false
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

    /// 检查目标交易前后交易中是否有Jito小费地址，并返回小费交易的详细信息
    ///
    /// # 参数
    /// * `block_transactions` - 区块中的所有交易
    /// * `target_index` - 目标交易在区块中的索引
    ///
    /// # 返回值
    /// 返回包含以下信息的元组，如果没有找到Jito小费则返回None:
    /// * 小费交易索引
    /// * 小费地址
    /// * 小费金额
    /// * 是否在目标交易前面
    /// * 捆绑包交易列表
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
                // Jito小费在前面，捆绑该交易+往后4个交易（包含目标交易）
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
                // Jito小费在后面，捆绑该交易+往前4个交易（包含目标交易）
                let bundle_start = i.saturating_sub(4);
                let bundle_transactions = block_transactions[bundle_start..=i].to_vec();
                return Some((i, tip_account, tip_amount, false, bundle_transactions));
            }
        }

        None
    }

    /// 检查单个交易是否包含Jito小费
    /// 返回: (小费地址, 小费金额)
    fn check_single_transaction_for_jito_tip(&self, tx: &Transaction) -> Option<(String, u64)> {
        // 首先找到所有Jito小费地址在账户列表中的索引
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

        // 检查每个指令是否包含Jito小费地址的索引
        for instruction in &tx.transaction.message.instructions {
            // 获取程序ID
            let program_id = tx
                .transaction
                .message
                .account_keys
                .get(instruction.program_id_index as usize)?;

            // 检查指令的账户索引列表是否包含任何Jito小费地址的索引
            for &account_index in &instruction.accounts {
                for &(jito_index, ref jito_address) in &jito_tip_indices {
                    if account_index as usize == jito_index {
                        // 进一步检查是否为系统程序转账指令
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
                // 标准系统程序转账格式
                u64::from_le_bytes(data.get(4..12)?.try_into().ok()?)
            }
            8 => {
                // 简化的转账格式 (只包含金额)
                u64::from_le_bytes(data.as_slice().try_into().ok()?)
            }
            len if len >= 12 => {
                // 尝试从数据中提取金额
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

    /// 检测交易列表中是否存在三明治攻击 - 基于账户交集分析
    ///
    /// # 参数
    /// * `transactions` - 交易列表（通常是Jito捆绑包中的交易）
    /// * `target_signature` - 目标交易的签名
    ///
    /// # 返回值
    /// 如果检测到三明治攻击，返回包含攻击详情和损失估算的结构体，否则返回None
    pub fn detect_sandwich_attack(
        &self,
        transactions: &[Transaction],
        target_signature: &str,
    ) -> Option<SandwichDetails> {
        let target_index = transactions
            .iter()
            .position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        // 检查目标交易是否是DEX交易类型
        if !self.is_dex_transaction(target_tx) {
            return None;
        }

        // 获取目标交易的过滤后账户（排除系统账户、Jito小费账户、小额转账账户）
        let target_accounts = self.extract_filtered_accounts(target_tx);
        if target_accounts.is_empty() {
            return None;
        }

        debug!("Target transaction filtered accounts: {}", target_accounts.len());

        // 寻找前两个交易中与目标交易有账户交集的交易
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

        // 寻找后两个交易中与目标交易有账户交集的交易
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

        // 检查前后交易是否有相等的账户交集（三明治攻击特征）
        for (front_tx, front_intersection) in &front_candidates {
            for (back_tx, back_intersection) in &back_candidates {
                // 检查前后交易的账户交集是否相当（表示与同一个池子交互）
                let intersection_similarity =
                    self.calculate_intersection_similarity(front_intersection, back_intersection);

                if intersection_similarity >= self.config.similarity_threshold {
                    // 达到配置的相似度阈值认为是同一个池子
                    //
                    info!(
                        "{} {:.1}%",
                        self.locale.sandwich_pattern_detected(),
                        intersection_similarity * 100.0
                    );

                    // 合并前后交易的账户交集作为最终交集
                    let mut combined_intersection = front_intersection.clone();
                    for account in back_intersection {
                        if !combined_intersection.contains(account) {
                            combined_intersection.push(account.clone());
                        }
                    }

                    // 计算用户损失
                    let user_loss = self.calculate_sandwich_loss(
                        transactions,
                        target_index,
                        &front_tx.signature,
                        &back_tx.signature,
                        &combined_intersection,
                    );

                    return Some(SandwichDetails {
                        front_tx: front_tx.signature.clone(),
                        back_tx: back_tx.signature.clone(),
                        account_intersection: combined_intersection,
                        user_loss,
                    });
                }
            }
        }

        None
    }

    /// 检测交易列表中是否存在抢跑攻击 - 基于账户交集分析
    ///
    /// # 参数
    /// * `transactions` - 交易列表（通常是Jito捆绑包中的交易）
    /// * `target_signature` - 目标交易的签名
    ///
    /// # 返回值
    /// 如果检测到抢跑攻击，返回包含攻击详情的结构体，否则返回None
    pub fn detect_frontrun_attack(
        &self,
        transactions: &[Transaction],
        target_signature: &str,
    ) -> Option<FrontrunDetails> {
        let target_index = transactions
            .iter()
            .position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        // 检查目标交易是否是DEX交易类型
        if !self.is_dex_transaction(target_tx) {
            return None;
        }

        // 获取目标交易的过滤后账户
        let target_accounts = self.extract_filtered_accounts(target_tx);
        if target_accounts.is_empty() {
            return None;
        }

        debug!(
            "Front-run detection - target transaction filtered accounts: {}",
            target_accounts.len()
        );

        // 在目标交易前面的几个交易中寻找抢跑攻击
        for i in (0..target_index).rev() {
            let potential_frontrun = &transactions[i];

            // 检查是否是DEX交易类型
            if !self.is_dex_transaction(potential_frontrun) {
                continue;
            }

            // 获取潜在抢跑交易的过滤后账户
            let frontrun_accounts = self.extract_filtered_accounts(potential_frontrun);

            // 计算账户交集
            let intersection: Vec<String> = target_accounts
                .intersection(&frontrun_accounts)
                .cloned()
                .collect();

            // 如果存在账户交集，则判定为抢跑攻击
            if !intersection.is_empty() {
                info!("{} {}", self.locale.frontrun_pattern_detected(), intersection.len());

                return Some(FrontrunDetails {
                    front_tx: potential_frontrun.signature.clone(),
                    victim_tx: target_tx.signature.clone(),
                    account_intersection: intersection,
                });
            }
        }

        None
    }

    /// 提取交易中的过滤后账户（只提取可写账户，排除Jito小费账户、小额转账账户）
    fn extract_filtered_accounts(&self, tx: &Transaction) -> HashSet<String> {
        let mut filtered_accounts = HashSet::new();

        // 直接检查账户的可写性，不依赖外部client
        // 获取所有指令中的可写账户
        for instruction in &tx.transaction.message.instructions {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(instruction.program_id_index as usize)
            {
                // 对于系统程序指令，检查是否为小额转账
                if program_id == SYSTEM {
                    if self.is_small_transfer_instruction(
                        instruction,
                        &tx.transaction.message.account_keys,
                    ) {
                        continue; // 跳过小额转账账户
                    }
                }

                for &acc_index in &instruction.accounts {
                    if let Some(account) =
                        tx.transaction.message.account_keys.get(acc_index as usize)
                    {
                        // 检查账户是否可写
                        if !self.is_account_writable(acc_index as usize, &tx.transaction.message) {
                            continue; // 跳过只读账户
                        }

                        // 排除Jito小费账户
                        if JITO_TIP_ACCOUNTS.contains(&account.as_str()) {
                            continue;
                        }

                        filtered_accounts.insert(account.clone());
                    }
                }
            }
        }

        // 额外过滤：确保账户地址有效
        filtered_accounts.retain(|account| {
            // 移除看起来像程序派生地址的长账户（超过44字符的通常是错误或特殊账户）
            account.len() <= 44 &&
            // 确保是有效的base58字符
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

    /// 检查指令是否为小额转账（小于0.001 SOL）
    fn is_small_transfer_instruction(
        &self,
        instruction: &crate::client::Instruction,
        account_keys: &[String],
    ) -> bool {
        // 只检查系统程序转账指令
        if let Some(program_id) = account_keys.get(instruction.program_id_index as usize) {
            if program_id != SYSTEM {
                return false;
            }
        } else {
            return false;
        }

        // 解析指令数据获取转账金额
        if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
            let amount = if data.len() == 12 && data[0..4] == [2, 0, 0, 0] {
                // 标准系统程序转账格式
                u64::from_le_bytes(data[4..12].try_into().unwrap_or([0; 8]))
            } else if data.len() == 8 {
                // 简化的转账格式 (只包含金额)
                u64::from_le_bytes(data.try_into().unwrap_or([0; 8]))
            } else if data.len() >= 12 {
                // 尝试从数据中提取金额
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

    /// 检查交易是否为DEX交易 - 改进版本，不仅依赖程序ID
    fn is_dex_transaction(&self, tx: &Transaction) -> bool {
        // 首先检查已知的DEX程序
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

        // 如果没有已知DEX程序，通过账户特征判断是否为交易
        self.is_likely_swap_transaction(tx)
    }

    /// 通过账户特征判断是否可能是swap交易
    fn is_likely_swap_transaction(&self, tx: &Transaction) -> bool {
        // 检查交易特征：
        // 1. 账户数量较多（swap通常涉及多个账户）
        // 2. 有多个指令
        // 3. 不是简单的系统程序交易

        let account_count = tx.transaction.message.account_keys.len();
        let _instruction_count = tx.transaction.message.instructions.len();

        // swap交易通常涉及至少配置的最小账户数量（用户钱包、token账户、池子账户、程序等）
        let has_multiple_accounts = account_count >= self.config.trade_size.min_swap_accounts;

        // 检查是否有非系统程序的指令
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

        // 检查是否有token相关的账户特征
        let has_token_accounts = self.has_token_account_patterns(tx);

        has_multiple_accounts && has_non_system_instructions && has_token_accounts
    }

    /// 检查是否有token账户的特征
    fn has_token_account_patterns(&self, tx: &Transaction) -> bool {
        // 检查账户地址的特征，token账户通常是base58编码的44字符长度
        let typical_token_account_count = tx
            .transaction
            .message
            .account_keys
            .iter()
            .filter(|key| key.len() == 44) // 典型的Solana账户地址长度
            .count();

        // 如果有多个典型长度的账户，可能是token相关交易
        typical_token_account_count >= 4
    }

    /// 计算三明治攻击中的用户损失
    /// 通过多种方法分析MEV攻击对用户造成的实际损失
    fn calculate_sandwich_loss(
        &self,
        transactions: &[Transaction],
        target_index: usize,
        front_tx_sig: &str,
        back_tx_sig: &str,
        shared_accounts: &[String],
    ) -> Option<UserLoss> {
        debug!("{}", self.locale.calculating_sandwich_loss());

        // 获取三笔交易
        let target_tx = &transactions[target_index];
        let front_tx = transactions
            .iter()
            .find(|tx| tx.signature == front_tx_sig)?;
        let back_tx = transactions.iter().find(|tx| tx.signature == back_tx_sig)?;

        // 改进的多方法分析，收集所有可能的结果
        let mut possible_losses = Vec::new();

        // 方法1: 改进的价格影响分析法
        if let Some(loss) = self.analyze_price_impact_loss_v2(front_tx, target_tx, back_tx, shared_accounts) {
            possible_losses.push(loss);
        }

        // 方法2: 改进的代币流动分析法
        if let Some(loss) = self.analyze_token_flow_loss(front_tx, target_tx, back_tx, shared_accounts) {
            possible_losses.push(loss);
        }

        // 方法3: 改进的攻击者利润分析法
        if let Some(loss) = self.analyze_attacker_profit_loss(front_tx, target_tx, back_tx) {
            possible_losses.push(loss);
        }

        // 方法4: 保守的滑点估算法
        let conservative_loss = self.estimate_conservative_slippage_loss(target_tx, shared_accounts);
        possible_losses.push(conservative_loss);

        // 选择最佳结果（基于置信度和验证）
        self.select_best_loss_estimation(possible_losses)
    }

    /// 改进的价格影响分析法 V2
    fn analyze_price_impact_loss_v2(
        &self,
        front_tx: &Transaction,
        target_tx: &Transaction,
        back_tx: &Transaction,
        shared_accounts: &[String],
    ) -> Option<UserLoss> {
        if shared_accounts.is_empty() {
            return None;
        }

        let target_value = self.analyze_trade_value(target_tx);
        let front_value = self.analyze_trade_value(front_tx);
        let back_value = self.analyze_trade_value(back_tx);

        if target_value.estimated_total_value == 0 {
            return None;
        }

        // 改进的价格影响计算
        let market_impact_ratio = self.calculate_market_impact_ratio(&front_value, &target_value, shared_accounts);
        let estimated_loss = (target_value.estimated_total_value as f64 * market_impact_ratio) as u64;

        // 改进的MEV利润计算：基于净收益而非交易规模
        let mev_profit = self.calculate_net_mev_profit(&front_value, &back_value);

        if estimated_loss > 0 {
            let loss_percentage = (estimated_loss as f64 / target_value.estimated_total_value as f64) * 100.0;
            let confidence = self.calculate_loss_confidence(&target_value, &front_value, &back_value, shared_accounts);
            let validation_passed = self.validate_loss_calculation(estimated_loss, mev_profit, target_value.estimated_total_value);

            Some(UserLoss {
                estimated_loss_lamports: estimated_loss,
                loss_percentage: loss_percentage.min(self.config.price_impact.max_loss_percentage),
                calculation_method: self.locale.price_impact_method_name().to_string(),
                mev_profit_lamports: mev_profit,
                confidence_score: confidence,
                validation_passed,
            })
        } else {
            None
        }
    }

    /// 改进的代币流动分析法
    fn analyze_token_flow_loss(
        &self,
        front_tx: &Transaction,
        target_tx: &Transaction,
        back_tx: &Transaction,
        shared_accounts: &[String],
    ) -> Option<UserLoss> {
        let target_flow = self.analyze_token_flow(target_tx);
        let front_flow = self.analyze_token_flow(front_tx);  
        let back_flow = self.analyze_token_flow(back_tx);

        if target_flow.estimated_token_value == 0 {
            return None;
        }

        // 基于流动性影响计算损失
        let liquidity_impact = self.calculate_liquidity_impact(&front_flow, &target_flow, shared_accounts);
        let estimated_loss = (target_flow.estimated_token_value as f64 * liquidity_impact) as u64;

        // 基于净流动计算MEV利润
        let mev_profit = self.calculate_flow_based_profit(&front_flow, &back_flow);

        if estimated_loss > 0 {
            let loss_percentage = (estimated_loss as f64 / target_flow.estimated_token_value as f64) * 100.0;
            let confidence = 0.7; // 代币流动分析的基础置信度
            let validation_passed = self.validate_loss_calculation(estimated_loss, mev_profit, target_flow.estimated_token_value);

            Some(UserLoss {
                estimated_loss_lamports: estimated_loss,
                loss_percentage: loss_percentage.min(self.config.token_balance.max_loss_percentage),
                calculation_method: self.locale.token_balance_method_name().to_string(),
                mev_profit_lamports: mev_profit,
                confidence_score: confidence,
                validation_passed,
            })
        } else {
            None
        }
    }

    /// 改进的攻击者利润分析法
    fn analyze_attacker_profit_loss(
        &self,
        front_tx: &Transaction,
        target_tx: &Transaction,
        back_tx: &Transaction,
    ) -> Option<UserLoss> {
        let attacker_addresses = self.identify_potential_attackers(front_tx, back_tx)?;
        let target_value = self.analyze_trade_value(target_tx);
        
        if target_value.estimated_total_value == 0 {
            return None;
        }

        // 基于攻击者实际收益计算
        let gross_profit = self.calculate_attacker_gross_profit(front_tx, back_tx, &attacker_addresses);
        let transaction_costs = self.estimate_transaction_costs(front_tx, back_tx);
        let net_profit = gross_profit.saturating_sub(transaction_costs);

        if net_profit > 0 {
            // 用户损失 = 攻击者净利润 * 分配比例
            let user_loss_ratio = self.calculate_user_loss_ratio(target_value.estimated_total_value, gross_profit);
            let estimated_loss = (net_profit as f64 * user_loss_ratio) as u64;
            
            let loss_percentage = (estimated_loss as f64 / target_value.estimated_total_value as f64) * 100.0;
            let confidence = 0.8; // 基于实际利润的分析置信度较高
            let validation_passed = self.validate_loss_calculation(estimated_loss, net_profit, target_value.estimated_total_value);

            Some(UserLoss {
                estimated_loss_lamports: estimated_loss,
                loss_percentage: loss_percentage.min(self.config.sol_balance.max_loss_percentage),
                calculation_method: self.locale.sol_balance_method_name().to_string(),
                mev_profit_lamports: net_profit,
                confidence_score: confidence,
                validation_passed,
            })
        } else {
            None
        }
    }

    /// 保守的滑点估算法（作为兜底方案）
    fn estimate_conservative_slippage_loss(
        &self,
        target_tx: &Transaction,
        shared_accounts: &[String],
    ) -> UserLoss {
        let target_value = self.analyze_trade_value(target_tx);
        let base_slippage = self.config.slippage.base_slippage;
        
        // 更保守的滑点计算
        let complexity_adjustment = 1.0 + (shared_accounts.len() as f64 * 0.1);
        let instruction_adjustment = 1.0 + (target_tx.transaction.message.instructions.len() as f64 * 0.05);
        
        let conservative_slippage = base_slippage * complexity_adjustment * instruction_adjustment * 0.5; // 更保守
        let estimated_loss = (target_value.estimated_total_value as f64 * conservative_slippage) as u64;

        let validation_passed = estimated_loss <= target_value.estimated_total_value / 10; // 不超过10%

        UserLoss {
            estimated_loss_lamports: estimated_loss,
            loss_percentage: (conservative_slippage * 100.0).min(self.config.slippage.max_loss_percentage),
            calculation_method: self.locale.slippage_method_name().to_string(),
            mev_profit_lamports: estimated_loss, // 保守估算：假设等于用户损失
            confidence_score: 0.5, // 保守估算的置信度较低
            validation_passed,
        }
    }

    /// 方法1: 价格影响分析法 - 通过分析池子状态变化计算损失
    fn analyze_price_impact_loss(
        &self,
        front_tx: &Transaction,
        target_tx: &Transaction,
        back_tx: &Transaction,
        shared_accounts: &[String],
    ) -> Option<UserLoss> {
        if shared_accounts.is_empty() {
            return None;
        }

        // 分析用户交易的规模
        let user_trade_size = self.estimate_trade_size(target_tx);
        if user_trade_size == 0 {
            return None;
        }

        // 计算攻击者通过前后交易造成的价格影响
        let front_impact = self.estimate_trade_size(front_tx);
        let back_impact = self.estimate_trade_size(back_tx);

        if front_impact > 0 && back_impact > 0 {
            // 计算由于价格影响导致的用户损失
            // 损失 = 用户交易规模 × 价格影响百分比
            let price_impact_ratio = (front_impact as f64
                / (front_impact + user_trade_size) as f64)
                * self.config.price_impact.price_impact_ratio;
            let estimated_loss = (user_trade_size as f64 * price_impact_ratio) as u64;

            // 计算MEV攻击者的净利润
            let mev_profit = back_impact.saturating_sub(front_impact);

            if estimated_loss > 0 {
                let loss_percentage = (estimated_loss as f64 / user_trade_size as f64) * 100.0;

                return Some(UserLoss {
                    estimated_loss_lamports: estimated_loss,
                    loss_percentage: loss_percentage
                        .min(self.config.price_impact.max_loss_percentage),
                    calculation_method: self.locale.price_impact_method_name().to_string(),
                    mev_profit_lamports: mev_profit,
                    confidence_score: 0.6, // 旧方法的默认置信度
                    validation_passed: self.validate_loss_calculation(estimated_loss, mev_profit, user_trade_size),
                });
            }
        }

        None
    }

    /// 方法2: Token余额变化分析法 - 分析用户实际损失的token数量
    fn analyze_token_balance_changes(
        &self,
        front_tx: &Transaction,
        target_tx: &Transaction,
        back_tx: &Transaction,
        shared_accounts: &[String],
    ) -> Option<UserLoss> {
        // 估算用户的交易规模
        let user_trade_size = self.estimate_trade_size(target_tx);
        if user_trade_size == 0 {
            return None;
        }

        // 分析共享账户数量 - 更多共享账户表示更大的市场影响
        let market_impact_factor = (shared_accounts.len() as f64).sqrt();

        // 计算攻击者的交易规模
        let attacker_front_size = self.estimate_trade_size(front_tx);
        let attacker_back_size = self.estimate_trade_size(back_tx);

        if attacker_front_size > 0 && attacker_back_size > 0 {
            // 计算相对交易规模影响
            let relative_impact =
                attacker_front_size as f64 / (attacker_front_size + user_trade_size) as f64;

            // 估算用户损失 = 交易规模 × 相对影响 × 市场影响因子
            let estimated_loss = (user_trade_size as f64
                * relative_impact
                * market_impact_factor
                * self.config.token_balance.loss_coefficient)
                as u64;

            // MEV攻击者利润估算
            let mev_profit = (attacker_back_size as f64 * 0.8) as u64;

            if estimated_loss > 0 {
                let loss_percentage = (estimated_loss as f64 / user_trade_size as f64) * 100.0;

                return Some(UserLoss {
                    estimated_loss_lamports: estimated_loss,
                    loss_percentage: loss_percentage
                        .min(self.config.token_balance.max_loss_percentage),
                    calculation_method: self.locale.token_balance_method_name().to_string(),
                    mev_profit_lamports: mev_profit,
                    confidence_score: 0.5, // 旧方法的默认置信度
                    validation_passed: self.validate_loss_calculation(estimated_loss, mev_profit, user_trade_size),
                });
            }
        }

        None
    }

    /// 方法4: 滑点估算法 - 基于交易规模和市场深度
    fn estimate_slippage_loss(
        &self,
        target_tx: &Transaction,
        shared_accounts: &[String],
    ) -> UserLoss {
        let user_trade_size = self.estimate_trade_size(target_tx);
        let instruction_count = target_tx.transaction.message.instructions.len();

        // 基础滑点估算
        let base_slippage = self.config.slippage.base_slippage;

        // 根据共享账户数量调整 (更多共享账户意味着更复杂的交易)
        let complexity_factor =
            1.0 + (shared_accounts.len() as f64 * self.config.slippage.complexity_factor);

        // 根据指令数量调整
        let instruction_factor =
            1.0 + (instruction_count as f64 * self.config.slippage.instruction_factor);

        // 计算最终滑点
        let final_slippage = base_slippage * complexity_factor * instruction_factor;
        let estimated_loss = (user_trade_size as f64 * final_slippage) as u64;

        UserLoss {
            estimated_loss_lamports: estimated_loss,
            loss_percentage: (final_slippage * 100.0).min(self.config.slippage.max_loss_percentage),
            calculation_method: self.locale.slippage_method_name().to_string(),
            mev_profit_lamports: estimated_loss, // 假设MEV利润等于用户损失
            confidence_score: 0.3, // 旧滑点方法的置信度较低
            validation_passed: self.validate_loss_calculation(estimated_loss, estimated_loss, user_trade_size),
        }
    }

    /// 改进的交易价值分析 - 更准确的估算方法
    fn analyze_trade_value(&self, tx: &Transaction) -> TradeValue {
        // 方法1: SOL转账金额分析
        let sol_amount = self.extract_sol_transfer_amount(tx);
        
        // 方法2: 指令复杂度分析（权重调整）
        let instruction_count = tx.transaction.message.instructions.len();
        let instruction_complexity = self.calculate_instruction_complexity(tx);
        
        // 方法3: 账户复杂度分析（只计算可写账户）
        let writable_accounts = self.count_writable_accounts(tx);
        let account_complexity = writable_accounts as u64 * self.config.trade_size.account_factor_value;
        
        // 方法4: 基于交易模式的价值估算
        let pattern_value = self.estimate_value_by_pattern(tx);
        
        // 综合评估
        let base_value = sol_amount + instruction_complexity + account_complexity + pattern_value;
        let estimated_total_value = base_value.max(self.config.trade_size.min_trade_size);
        
        // 计算置信度
        let confidence = self.calculate_value_confidence(sol_amount, instruction_count, writable_accounts);
        
        TradeValue {
            sol_amount,
            instruction_complexity,
            account_complexity,
            estimated_total_value,
            confidence,
        }
    }

    /// 计算指令复杂度（改进版）
    fn calculate_instruction_complexity(&self, tx: &Transaction) -> u64 {
        let mut complexity = 0u64;
        
        for instruction in &tx.transaction.message.instructions {
            if let Some(program_id) = tx.transaction.message.account_keys.get(instruction.program_id_index as usize) {
                // 根据程序类型给予不同权重
                let weight = match program_id.as_str() {
                    // DEX程序权重更高
                    RAYDIUM_AMM | RAYDIUM_CLMM | ORCA_WHIRLPOOLS | ORCA_V1 => 3.0,
                    JUPITER | SERUM_DEX => 2.5,
                    PUMP_FUN => 2.0,
                    SYSTEM => 0.5, // 系统程序权重较低
                    _ => 1.0, // 其他程序默认权重
                };
                
                complexity += (self.config.trade_size.instruction_complexity_value as f64 * weight) as u64;
            }
        }
        
        complexity
    }

    /// 计算可写账户数量
    fn count_writable_accounts(&self, tx: &Transaction) -> usize {
        let total_accounts = tx.transaction.message.account_keys.len();
        let mut writable_count = 0;
        
        for i in 0..total_accounts {
            if self.is_account_writable(i, &tx.transaction.message) {
                writable_count += 1;
            }
        }
        
        writable_count
    }

    /// 基于交易模式估算价值
    fn estimate_value_by_pattern(&self, tx: &Transaction) -> u64 {
        let account_count = tx.transaction.message.account_keys.len();
        let instruction_count = tx.transaction.message.instructions.len();
        
        // 根据交易模式特征评估
        if account_count >= 15 && instruction_count >= 3 {
            // 复杂交易模式（可能是大额swap）
            self.config.trade_size.min_trade_size * 5
        } else if account_count >= 10 && instruction_count >= 2 {
            // 中等复杂度交易
            self.config.trade_size.min_trade_size * 2
        } else if account_count >= 6 {
            // 简单swap交易
            self.config.trade_size.min_trade_size
        } else {
            // 很可能不是swap交易
            0
        }
    }

    /// 计算价值估算的置信度
    fn calculate_value_confidence(&self, sol_amount: u64, instruction_count: usize, writable_accounts: usize) -> f64 {
        let mut confidence = 0.0;
        
        // SOL金额置信度（30%权重）
        if sol_amount > self.config.small_transfer_threshold {
            confidence += 0.3 * (sol_amount as f64 / (self.config.trade_size.min_trade_size as f64 * 10.0)).min(1.0);
        }
        
        // 指令数量置信度（25%权重）
        confidence += 0.25 * ((instruction_count as f64 / 5.0).min(1.0));
        
        // 可写账户置信度（25%权重）
        confidence += 0.25 * ((writable_accounts as f64 / 10.0).min(1.0));
        
        // 基础置信度（20%权重） - 如果是识别的DEX交易
        // 注意：这里需要一个tx参数，但为了简化，我们先跳过DEX检查
        confidence += 0.2; // 给予基础置信度
        
        confidence.min(1.0)
    }

    /// 保持向后兼容的简化接口
    fn estimate_trade_size(&self, tx: &Transaction) -> u64 {
        self.analyze_trade_value(tx).estimated_total_value
    }

    /// 分析SOL余额变化来估算损失 (兜底方法)
    fn analyze_sol_balance_changes(
        &self,
        front_tx: &Transaction,
        target_tx: &Transaction,
        back_tx: &Transaction,
    ) -> Option<UserLoss> {
        // 查找攻击者账户 (在前后交易中都出现的签名账户)
        let front_signers: HashSet<&String> = front_tx
            .transaction
            .message
            .account_keys
            .iter()
            .take(
                front_tx
                    .transaction
                    .message
                    .header
                    .as_ref()?
                    .num_required_signatures as usize,
            )
            .collect();
        let back_signers: HashSet<&String> = back_tx
            .transaction
            .message
            .account_keys
            .iter()
            .take(
                back_tx
                    .transaction
                    .message
                    .header
                    .as_ref()?
                    .num_required_signatures as usize,
            )
            .collect();

        // 找到共同的签名者 (可能是攻击者)
        let common_signers: Vec<&String> =
            front_signers.intersection(&back_signers).cloned().collect();

        if !common_signers.is_empty() {
            // 分析前后交易中的SOL转账金额
            let front_sol_amount = self.extract_sol_transfer_amount(front_tx);
            let back_sol_amount = self.extract_sol_transfer_amount(back_tx);
            let target_sol_amount = self.extract_sol_transfer_amount(target_tx);

            debug!("{} {}", self.locale.front_tx_sol_transfer(), front_sol_amount);
            debug!("{} {}", self.locale.target_tx_sol_transfer(), target_sol_amount);
            debug!("{} {}", self.locale.back_tx_sol_transfer(), back_sol_amount);

            // 估算MEV利润 = 后置交易收益 - 前置交易成本
            let mev_profit = back_sol_amount.saturating_sub(front_sol_amount);

            if mev_profit > 0 {
                // 改进的损失计算：基于交易规模的比例
                let user_trade_size = target_sol_amount.max(self.estimate_trade_size(target_tx));
                let estimated_loss = if user_trade_size > 0 {
                    // 损失 = MEV利润 × (用户交易规模 / 总交易规模) × 影响因子
                    let total_volume = front_sol_amount + user_trade_size + back_sol_amount;
                    let user_ratio = user_trade_size as f64 / total_volume as f64;
                    (mev_profit as f64 * user_ratio * self.config.sol_balance.impact_factor) as u64
                } else {
                    (mev_profit as f64 * self.config.sol_balance.conservative_ratio) as u64
                    // 保守估算
                };

                let loss_percentage = if user_trade_size > 0 {
                    (estimated_loss as f64 / user_trade_size as f64) * 100.0
                } else {
                    1.0 // 默认1%
                };

                return Some(UserLoss {
                    estimated_loss_lamports: estimated_loss,
                    loss_percentage: loss_percentage
                        .min(self.config.sol_balance.max_loss_percentage),
                    calculation_method: self.locale.sol_balance_method_name().to_string(),
                    mev_profit_lamports: mev_profit,
                    confidence_score: 0.4, // 旧SOL余额方法的置信度
                    validation_passed: self.validate_loss_calculation(estimated_loss, mev_profit, user_trade_size),
                });
            }
        }

        None
    }

    /// 提取交易中的SOL转账金额
    fn extract_sol_transfer_amount(&self, tx: &Transaction) -> u64 {
        let mut total_amount = 0u64;

        for instruction in &tx.transaction.message.instructions {
            // 检查是否为系统程序转账指令
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(instruction.program_id_index as usize)
            {
                if program_id == SYSTEM {
                    if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
                        let amount = if data.len() == 12 && data[0..4] == [2, 0, 0, 0] {
                            // 标准系统程序转账格式
                            u64::from_le_bytes(data[4..12].try_into().unwrap_or([0; 8]))
                        } else if data.len() == 8 {
                            // 简化的转账格式
                            u64::from_le_bytes(data.try_into().unwrap_or([0; 8]))
                        } else if data.len() >= 12 {
                            // 尝试从数据中提取金额
                            u64::from_le_bytes(data[4..12].try_into().unwrap_or([0; 8]))
                        } else {
                            0
                        };

                        if amount > self.config.small_transfer_threshold {
                            total_amount += amount;
                        }
                    }
                }
            }
        }

        total_amount
    }

    // =============================================================================
    // 新增的辅助方法
    // =============================================================================

    /// 选择最佳的损失估算结果
    fn select_best_loss_estimation(&self, possible_losses: Vec<UserLoss>) -> Option<UserLoss> {
        if possible_losses.is_empty() {
            return None;
        }

        // 优先选择通过验证且置信度最高的结果
        let validated_losses: Vec<&UserLoss> = possible_losses
            .iter()
            .filter(|loss| loss.validation_passed)
            .collect();

        let best_loss = if !validated_losses.is_empty() {
            // 在通过验证的结果中选择置信度最高的
            validated_losses
                .into_iter()
                .max_by(|a, b| a.confidence_score.partial_cmp(&b.confidence_score).unwrap())?
        } else {
            // 如果没有通过验证的结果，选择置信度最高的
            possible_losses
                .iter()
                .max_by(|a, b| a.confidence_score.partial_cmp(&b.confidence_score).unwrap())?
        };

        Some(best_loss.clone())
    }

    /// 分析代币流动
    fn analyze_token_flow(&self, tx: &Transaction) -> TokenFlow {
        let sol_transfers = self.extract_sol_transfer_amount(tx) as i64;
        let net_sol_change = sol_transfers; // 简化：假设SOL转出为负，转入为正
        
        let instruction_count = tx.transaction.message.instructions.len();
        let writable_account_count = self.count_writable_accounts(tx);
        
        // 基于交易复杂度估算代币价值
        let estimated_token_value = self.analyze_trade_value(tx).estimated_total_value;

        TokenFlow {
            net_sol_change,
            instruction_count,
            writable_account_count,
            estimated_token_value,
        }
    }

    /// 计算市场影响比例
    fn calculate_market_impact_ratio(&self, front_value: &TradeValue, target_value: &TradeValue, shared_accounts: &[String]) -> f64 {
        if target_value.estimated_total_value == 0 {
            return 0.0;
        }

        // 基于攻击者交易规模相对于用户交易规模的比例
        let size_ratio = front_value.estimated_total_value as f64 / (front_value.estimated_total_value + target_value.estimated_total_value) as f64;
        
        // 基于共享账户数量的影响调整
        let account_impact = (shared_accounts.len() as f64).sqrt() * 0.01;
        
        // 综合影响比例
        (size_ratio * self.config.price_impact.price_impact_ratio + account_impact).min(0.1) // 最大10%影响
    }

    /// 计算净MEV利润
    fn calculate_net_mev_profit(&self, front_value: &TradeValue, back_value: &TradeValue) -> u64 {
        // 简化计算：假设后置交易的80%是利润，减去前置交易成本
        let gross_profit = (back_value.sol_amount as f64 * 0.8) as u64;
        let front_cost = front_value.sol_amount;
        
        gross_profit.saturating_sub(front_cost)
    }

    /// 计算流动性影响
    fn calculate_liquidity_impact(&self, front_flow: &TokenFlow, target_flow: &TokenFlow, shared_accounts: &[String]) -> f64 {
        if target_flow.estimated_token_value == 0 {
            return 0.0;
        }

        // 基于攻击者对市场流动性的影响
        let liquidity_ratio = front_flow.estimated_token_value as f64 / (front_flow.estimated_token_value + target_flow.estimated_token_value) as f64;
        
        // 基于共享账户的复杂度调整
        let complexity_factor = (shared_accounts.len() as f64 / 10.0).min(1.0);
        
        (liquidity_ratio * self.config.token_balance.loss_coefficient * complexity_factor).min(0.05) // 最大5%
    }

    /// 基于流动计算MEV利润
    fn calculate_flow_based_profit(&self, front_flow: &TokenFlow, back_flow: &TokenFlow) -> u64 {
        // 基于净SOL变化计算利润
        let net_change = back_flow.net_sol_change - front_flow.net_sol_change;
        if net_change > 0 {
            net_change as u64
        } else {
            0
        }
    }

    /// 识别潜在攻击者地址
    fn identify_potential_attackers(&self, front_tx: &Transaction, back_tx: &Transaction) -> Option<Vec<String>> {
        // 改进的攻击者识别：基于签名者和资金流动模式
        let front_signers: HashSet<&String> = front_tx
            .transaction
            .message
            .account_keys
            .iter()
            .take(
                front_tx
                    .transaction
                    .message
                    .header
                    .as_ref()?
                    .num_required_signatures as usize,
            )
            .collect();
            
        let back_signers: HashSet<&String> = back_tx
            .transaction  
            .message
            .account_keys
            .iter()
            .take(
                back_tx
                    .transaction
                    .message  
                    .header
                    .as_ref()?
                    .num_required_signatures as usize,
            )
            .collect();

        let common_signers: Vec<String> = front_signers
            .intersection(&back_signers)
            .map(|s| (*s).clone())
            .collect();

        if common_signers.is_empty() {
            None
        } else {
            Some(common_signers)
        }
    }

    /// 计算攻击者总利润
    fn calculate_attacker_gross_profit(&self, front_tx: &Transaction, back_tx: &Transaction, _attacker_addresses: &[String]) -> u64 { 
        // 简化实现：基于SOL转账金额差
        let back_amount = self.extract_sol_transfer_amount(back_tx);
        let front_amount = self.extract_sol_transfer_amount(front_tx);
        
        back_amount.saturating_sub(front_amount)
    }

    /// 估算交易成本
    fn estimate_transaction_costs(&self, front_tx: &Transaction, back_tx: &Transaction) -> u64 {
        // 估算gas费用 (每个交易大约5000 lamports)
        let base_fee_per_tx = 5_000u64;
        let front_instructions = front_tx.transaction.message.instructions.len() as u64;
        let back_instructions = back_tx.transaction.message.instructions.len() as u64;
        
        // 基础费用 + 指令复杂度费用
        (base_fee_per_tx * 2) + ((front_instructions + back_instructions) * 1_000)
    }

    /// 计算用户损失比例
    fn calculate_user_loss_ratio(&self, user_trade_value: u64, attacker_gross_profit: u64) -> f64 {
        if attacker_gross_profit == 0 {
            return 0.0;
        }

        // 用户损失通常是攻击者利润的一部分，比例基于交易规模
        let total_volume = user_trade_value + attacker_gross_profit;
        let user_ratio = user_trade_value as f64 / total_volume as f64;
        
        // 用户承担的损失比例在30%-70%之间
        (user_ratio * 0.7).max(0.3).min(0.7)
    }

    /// 计算损失估算的置信度
    fn calculate_loss_confidence(
        &self,
        target_value: &TradeValue,
        front_value: &TradeValue,
        back_value: &TradeValue,
        shared_accounts: &[String],
    ) -> f64 {
        let mut confidence = 0.0;

        // 交易价值置信度（40%权重）
        confidence += 0.4 * ((target_value.confidence + front_value.confidence + back_value.confidence) / 3.0);

        // 共享账户数量置信度（30%权重）
        let account_confidence = (shared_accounts.len() as f64 / 10.0).min(1.0);
        confidence += 0.3 * account_confidence;

        // 交易规模合理性（20%权重）
        let size_reasonableness = if target_value.estimated_total_value > 0 {
            ((front_value.estimated_total_value + back_value.estimated_total_value) as f64 
             / target_value.estimated_total_value as f64).min(10.0) / 10.0
        } else {
            0.0
        };
        confidence += 0.2 * size_reasonableness;

        // 基础置信度（10%权重）
        confidence += 0.1;

        confidence.min(1.0)
    }

    /// 验证损失计算的合理性
    fn validate_loss_calculation(&self, estimated_loss: u64, mev_profit: u64, user_trade_value: u64) -> bool {
        // 验证条件1: 损失不能超过用户交易价值的20%
        if estimated_loss > user_trade_value / 5 {
            return false;
        }

        // 验证条件2: 损失不能为0（如果有MEV攻击应该有损失）
        if estimated_loss == 0 && mev_profit > 0 {
            return false;
        }

        // 验证条件3: MEV利润应该大于等于用户损失（攻击者不会亏本）
        if mev_profit > 0 && estimated_loss > mev_profit * 2 {
            return false;
        }

        // 验证条件4: 损失金额应该在合理范围内（不少于1000 lamports）
        if estimated_loss > 0 && estimated_loss < 1_000 {
            return false;
        }

        true
    }
}
