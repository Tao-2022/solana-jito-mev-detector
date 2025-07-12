use crate::client::Transaction;
use bs58;
use log::{debug, error, info, warn};
use std::collections::HashSet;

pub struct MevDetector;

pub struct SandwichDetails {
    pub front_tx: String,
    pub back_tx: String,
    pub account_intersection: Vec<String>, // 账户交集
}

pub struct FrontrunDetails {
    pub front_tx: String,
    pub victim_tx: String,
    pub account_intersection: Vec<String>, // 账户交集
}

// 主要 DEX 程序 ID
const RAYDIUM_AMM_PROGRAM_ID: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
const RAYDIUM_CLMM_PROGRAM_ID: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUQzGdR1qJRXgKhpNzc";
const ORCA_WHIRLPOOLS_PROGRAM_ID: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
const ORCA_V1_PROGRAM_ID: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const SERUM_DEX_PROGRAM_ID: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const JUPITER_PROGRAM_ID: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const PUMP_FUN_PROGRAM_ID: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";

// 小额转账阈值 (0.001 SOL = 1,000,000 lamports)
const SMALL_TRANSFER_THRESHOLD: u64 = 1_000_000;
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

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
const MEMO_PROGRAM_ID: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDgQdddcxFr";
const VOTE_PROGRAM_ID: &str = "Vote111111111111111111111111111111111111111";
// 添加更多可能的投票相关程序ID
const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";
const ALLOWED_PROGRAMS_FOR_SIMPLE_TRANSFER: [&str; 2] = [SYSTEM_PROGRAM_ID, MEMO_PROGRAM_ID];

impl MevDetector {
    /// 检查交易是否为简单的转账（仅涉及系统程序或Memo程序）。
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

    /// 检查交易是否为投票交易或其他系统维护交易
    pub fn is_vote_transaction(&self, tx: &Transaction) -> bool {
        use log::debug;

        // 检查账户列表中是否包含投票程序账户
        let has_vote_account = tx
            .transaction
            .message
            .account_keys
            .iter()
            .any(|account| account == VOTE_PROGRAM_ID);

        if has_vote_account {
            debug!("检测到投票交易（账户列表包含投票程序）: {}", tx.signature);
            return true;
        }

        // 检查是否有质押程序账户
        let has_stake_account = tx
            .transaction
            .message
            .account_keys
            .iter()
            .any(|account| account == STAKE_PROGRAM_ID);

        if has_stake_account {
            debug!("检测到质押交易（账户列表包含质押程序）: {}", tx.signature);
            return true;
        }

        // 检查程序ID（作为备用检测）
        let has_vote_program = tx.transaction.message.instructions.iter().any(|inst| {
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
        });

        if has_vote_program {
            debug!("检测到投票/质押交易（程序ID检测）: {}", tx.signature);
            return true;
        }

        false
    }

    /// 检查是否为已知的程序账户
    fn is_known_program_account(&self, account: &str) -> bool {
        // 检查是否为已知的DEX程序、系统程序或其他知名程序
        let known_programs = [
            RAYDIUM_AMM_PROGRAM_ID,
            RAYDIUM_CLMM_PROGRAM_ID,
            ORCA_WHIRLPOOLS_PROGRAM_ID,
            ORCA_V1_PROGRAM_ID,
            SERUM_DEX_PROGRAM_ID,
            JUPITER_PROGRAM_ID,
            PUMP_FUN_PROGRAM_ID,
            SYSTEM_PROGRAM_ID,
            MEMO_PROGRAM_ID,
            VOTE_PROGRAM_ID,
            STAKE_PROGRAM_ID,
        ];

        known_programs.contains(&account) || JITO_TIP_ACCOUNTS.contains(&account)
    }

    /// 检查目标交易前后交易中是否有Jito小费地址，并返回小费交易的详细信息
    /// 返回: (小费交易索引, 小费地址, 小费金额, 是否在目标交易前面, 捆绑包交易)
    pub fn check_jito_tip_in_nearby_transactions(
        &self,
        block_transactions: &[Transaction],
        target_index: usize,
    ) -> Option<(usize, String, u64, bool, Vec<Transaction>)> {
        // 打印交易信息
        info!("🔍 开始检查前后交易是否包含Jito小费:");
        let mut prev_count = 0;
        let mut next_count = 0;

        for (i, tx) in block_transactions.iter().enumerate() {
            if i < target_index {
                prev_count += 1;
                info!(
                    "    前第{}笔: https://solscan.io/tx/{}",
                    prev_count, tx.signature
                );
            } else if i > target_index {
                next_count += 1;
                info!(
                    "    后第{}笔: https://solscan.io/tx/{}",
                    next_count, tx.signature
                );
            }
        }

        // 先检查目标交易前面的交易
        for i in (0..target_index).rev() {
            let tx = &block_transactions[i];
            if let Some((tip_account, tip_amount)) = self.check_single_transaction_for_jito_tip(tx)
            {
                info!("✅ 在目标交易前面发现Jito小费交易，构建捆绑包...");
                // Jito小费在前面，捆绑该交易+往后4个交易（包含目标交易）
                let bundle_end = (i + 5).min(block_transactions.len());
                let bundle_transactions = block_transactions[i..bundle_end].to_vec();
                info!(
                    "📦 构建捆绑包: 从索引{}到{} (共{}个交易)",
                    i,
                    bundle_end - 1,
                    bundle_transactions.len()
                );
                return Some((i, tip_account, tip_amount, true, bundle_transactions));
            }
        }

        // 再检查目标交易后面的交易
        for i in (target_index + 1)..block_transactions.len() {
            let tx = &block_transactions[i];
            if let Some((tip_account, tip_amount)) = self.check_single_transaction_for_jito_tip(tx)
            {
                info!("✅ 在目标交易后面发现Jito小费交易，构建捆绑包...");
                // Jito小费在后面，捆绑该交易+往前4个交易（包含目标交易）
                let bundle_start = i.saturating_sub(4);
                let bundle_transactions = block_transactions[bundle_start..=i].to_vec();
                info!(
                    "📦 构建捆绑包: 从索引{}到{} (共{}个交易)",
                    bundle_start,
                    i,
                    bundle_transactions.len()
                );
                return Some((i, tip_account, tip_amount, false, bundle_transactions));
            }
        }

        info!("❌ 在前后交易中未发现Jito小费交易");
        None
    }

    /// 检查单个交易是否包含Jito小费
    /// 返回: (小费地址, 小费金额)
    fn check_single_transaction_for_jito_tip(&self, tx: &Transaction) -> Option<(String, u64)> {
        use log::{debug, info};

        info!("🔍 检查交易: {}", tx.signature);

        // 调试：打印所有账户
        debug!(
            "  📋 交易账户列表 ({} 个账户):",
            tx.transaction.message.account_keys.len()
        );
        for (i, account) in tx.transaction.message.account_keys.iter().enumerate() {
            debug!("    [{}] {}", i, account);
        }

        // 首先找到所有Jito小费地址在账户列表中的索引
        let mut jito_tip_indices = Vec::new();
        for (account_index, account) in tx.transaction.message.account_keys.iter().enumerate() {
            if JITO_TIP_ACCOUNTS.contains(&account.as_str()) {
                jito_tip_indices.push((account_index, account.clone()));
                info!(
                    "   在账户索引 {} 发现Jito小费地址: {}",
                    account_index, account
                );
            }
        }

        if jito_tip_indices.is_empty() {
            // 检查是否有任何账户看起来像Jito小费地址（调试用）
            info!("  交易账户列表中未包含已知Jito小费地址");
            for jito_addr in JITO_TIP_ACCOUNTS.iter() {
                info!("    - {}", jito_addr);
            }
            return None;
        }

        warn!(
            "  ⚠️ 交易账户列表中包含 {} 个Jito小费地址，开始解析指令",
            jito_tip_indices.len()
        );

        // 检查每个指令是否包含Jito小费地址的索引
        for (inst_idx, instruction) in tx.transaction.message.instructions.iter().enumerate() {
            // 获取程序ID
            let program_id = tx
                .transaction
                .message
                .account_keys
                .get(instruction.program_id_index as usize);

            debug!(
                "  指令 {}: program_id_index = {}, program_id = {:?}, accounts = {:?}",
                inst_idx, instruction.program_id_index, program_id, instruction.accounts
            );

            // 检查指令的账户索引列表是否包含任何Jito小费地址的索引
            for &account_index in &instruction.accounts {
                for &(jito_index, ref jito_address) in &jito_tip_indices {
                    if account_index as usize == jito_index {
                        debug!(
                            " ⚠️ 交易账户列表中包含 指令 {} 的账户索引 {} 匹配Jito小费地址: {}",
                            inst_idx, account_index, jito_address
                        );

                        // 进一步检查是否为系统程序转账指令
                        if program_id == Some(&SYSTEM_PROGRAM_ID.to_string()) {
                            debug!(" ✅ 确认为系统程序指令，分析转账金额");

                            if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
                                debug!("   指令数据长度: {}, 数据: {:?}", data.len(), data);

                                // 检查多种可能的转账指令格式
                                let amount = if data.len() == 12 && data[0..4] == [2, 0, 0, 0] {
                                    // 标准系统程序转账格式
                                    u64::from_le_bytes(data[4..12].try_into().unwrap())
                                } else if data.len() == 8 {
                                    // 简化的转账格式 (只包含金额)
                                    u64::from_le_bytes(data.try_into().unwrap())
                                } else if data.len() >= 8 {
                                    // 尝试从数据中提取金额 (可能在不同位置)
                                    if data.len() >= 12 {
                                        u64::from_le_bytes(data[4..12].try_into().unwrap())
                                    } else {
                                        u64::from_le_bytes(data[0..8].try_into().unwrap())
                                    }
                                } else {
                                    error!("    ❌ 无法解析转账金额，数据长度: {}", data.len());
                                    0
                                };

                                if amount > 0 {
                                    info!(
                                        "    💰 Jito小费金额: {} lamports ({:.9} SOL)",
                                        amount,
                                        amount as f64 / 1_000_000_000.0
                                    );
                                    // 返回小费地址和金额
                                    return Some((jito_address.clone(), amount));
                                } else {
                                    debug!("    ❌ 无法解析有效的转账金额");
                                }
                            } else {
                                debug!("    ❌ 无法解码指令数据");
                            }
                        } else {
                            debug!("    ❌ 不是系统程序指令: {:?}", program_id);
                        }
                    }
                }
            }
        }

        debug!("  ❌ 虽然账户列表包含Jito小费地址，但未在指令中找到相关转账");
        None
    }

    /// 检测交易列表中是否存在三明治攻击 - 基于账户交集分析
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

        info!("🎯 目标交易过滤后账户数量: {}", target_accounts.len());
        
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
                let intersection_similarity = self.calculate_intersection_similarity(
                    front_intersection, 
                    back_intersection
                );
                
                if intersection_similarity >= 0.7 { // 70%以上相似度认为是同一个池子
                    info!("🥪 发现三明治攻击模式: 前后交易与目标交易有相似的账户交集");
                    info!("  前置交易账户交集: {:?}", front_intersection);
                    info!("  后置交易账户交集: {:?}", back_intersection);
                    info!("  交集相似度: {:.2}%", intersection_similarity * 100.0);
                    
                    // 合并前后交易的账户交集作为最终交集
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
                    });
                }
            }
        }

        None
    }

    /// 检测交易列表中是否存在抢跑攻击 - 基于账户交集分析
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
                info!("🏃 发现抢跑攻击模式: 前置交易与目标交易存在账户交集");
                info!("  账户交集: {:?}", intersection);
                
                return Some(FrontrunDetails {
                    front_tx: potential_frontrun.signature.clone(),
                    victim_tx: target_tx.signature.clone(),
                    account_intersection: intersection,
                });
            }
        }

        None
    }

    /// 提取交易中的过滤后账户（排除系统账户、Jito小费账户、小额转账账户）
    fn extract_filtered_accounts(&self, tx: &Transaction) -> HashSet<String> {
        let mut filtered_accounts = HashSet::new();

        // 获取所有非系统程序的账户
        for instruction in &tx.transaction.message.instructions {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(instruction.program_id_index as usize)
            {
                // 跳过系统程序指令
                if program_id == SYSTEM_PROGRAM_ID {
                    // 对于系统程序指令，检查是否为小额转账
                    if self.is_small_transfer_instruction(instruction, &tx.transaction.message.account_keys) {
                        continue; // 跳过小额转账账户
                    }
                }

                for &acc_index in &instruction.accounts {
                    if let Some(account) = tx.transaction.message.account_keys.get(acc_index as usize) {
                        // 排除系统账户
                        if account == SYSTEM_PROGRAM_ID || account == MEMO_PROGRAM_ID {
                            continue;
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

        filtered_accounts
    }

    /// 检查指令是否为小额转账（小于0.001 SOL）
    fn is_small_transfer_instruction(&self, instruction: &crate::client::Instruction, account_keys: &[String]) -> bool {
        // 只检查系统程序转账指令
        if let Some(program_id) = account_keys.get(instruction.program_id_index as usize) {
            if program_id != SYSTEM_PROGRAM_ID {
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

            amount > 0 && amount < SMALL_TRANSFER_THRESHOLD
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
            RAYDIUM_AMM_PROGRAM_ID,
            RAYDIUM_CLMM_PROGRAM_ID,
            ORCA_WHIRLPOOLS_PROGRAM_ID,
            ORCA_V1_PROGRAM_ID,
            SERUM_DEX_PROGRAM_ID,
            JUPITER_PROGRAM_ID,
            PUMP_FUN_PROGRAM_ID,
        ];

        let has_known_dex = tx.transaction.message.instructions.iter().any(|inst| {
            if let Some(program_id) = tx.transaction.message.account_keys.get(inst.program_id_index as usize) {
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

        // swap交易通常涉及至少6个账户（用户钱包、token账户、池子账户、程序等）
        let has_multiple_accounts = account_count >= 6;

        // 检查是否有非系统程序的指令
        let has_non_system_instructions = tx.transaction.message.instructions.iter().any(|inst| {
            if let Some(program_id) = tx.transaction.message.account_keys.get(inst.program_id_index as usize) {
                program_id != SYSTEM_PROGRAM_ID && program_id != MEMO_PROGRAM_ID
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
}
