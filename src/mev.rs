use crate::client::Transaction;
use bs58;
use log::{debug, error, info, warn};
use std::collections::HashSet;

pub struct MevDetector;

pub struct SandwichDetails {
    pub front_tx: String,
    pub back_tx: String,
    pub account_intersection: Vec<String>, // 账户交集
    pub user_loss: Option<UserLoss>, // 用户损失计算结果
}

#[derive(Debug, Clone)]
pub struct UserLoss {
    pub estimated_loss_lamports: u64,
    pub loss_percentage: f64,
    pub calculation_method: String,
    pub mev_profit_lamports: u64, // MEV攻击者利润
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

// SPL Token 程序
const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

// 常见的系统代币账户
const WSOL_MINT: &str = "So11111111111111111111111111111111111111112"; // Wrapped SOL

// Solana 核心程序
const RENT_PROGRAM_ID: &str = "SysvarRent111111111111111111111111111111111";
const CLOCK_PROGRAM_ID: &str = "SysvarC1ock11111111111111111111111111111111";
const RECENT_BLOCKHASHES_PROGRAM_ID: &str = "SysvarRecentB1ockHashes11111111111111111111";
const EPOCH_SCHEDULE_PROGRAM_ID: &str = "SysvarEpochSchedu1e111111111111111111111111";
const FEES_PROGRAM_ID: &str = "SysvarFees111111111111111111111111111111111";
const SLOT_HASHES_PROGRAM_ID: &str = "SysvarS1otHashes111111111111111111111111111";
const SLOT_HISTORY_PROGRAM_ID: &str = "SysvarS1otHistory11111111111111111111111111";
const STAKE_HISTORY_PROGRAM_ID: &str = "SysvarStakeHistory1111111111111111111111111";

// BPF Loader 程序
const BPF_LOADER_PROGRAM_ID: &str = "BPFLoader1111111111111111111111111111111111";
const BPF_LOADER_2_PROGRAM_ID: &str = "BPFLoader2111111111111111111111111111111111";
const BPF_LOADER_UPGRADEABLE_PROGRAM_ID: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

// 其他常见程序
const CONFIG_PROGRAM_ID: &str = "Config1111111111111111111111111111111111111";
const FEATURE_PROGRAM_ID: &str = "Feature111111111111111111111111111111111111";
const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: &str = "AddressLookupTab1e1111111111111111111111111";

// Metaplex 相关程序（也很常见）
const METAPLEX_TOKEN_METADATA_PROGRAM_ID: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
const METAPLEX_AUCTION_HOUSE_PROGRAM_ID: &str = "hausS13jsjafwWwGqZTUQRmWyvyxn9EQpqMwV1PBBmk";

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
            // SPL Token 程序
            TOKEN_PROGRAM_ID,
            TOKEN_2022_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID,
            // 常见系统代币
            WSOL_MINT,
            // Solana 核心程序
            RENT_PROGRAM_ID,
            CLOCK_PROGRAM_ID,
            RECENT_BLOCKHASHES_PROGRAM_ID,
            EPOCH_SCHEDULE_PROGRAM_ID,
            FEES_PROGRAM_ID,
            SLOT_HASHES_PROGRAM_ID,
            SLOT_HISTORY_PROGRAM_ID,
            STAKE_HISTORY_PROGRAM_ID,
            // BPF Loader 程序
            BPF_LOADER_PROGRAM_ID,
            BPF_LOADER_2_PROGRAM_ID,
            BPF_LOADER_UPGRADEABLE_PROGRAM_ID,
            // 其他常见程序
            CONFIG_PROGRAM_ID,
            FEATURE_PROGRAM_ID,
            COMPUTE_BUDGET_PROGRAM_ID,
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            // Metaplex 相关程序
            METAPLEX_TOKEN_METADATA_PROGRAM_ID,
            METAPLEX_AUCTION_HOUSE_PROGRAM_ID,
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
        debug!("🎯 目标交易过滤后账户列表: {:?}", target_accounts);
        
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
                    
                    // 计算用户损失
                    let user_loss = self.calculate_sandwich_loss(
                        transactions, 
                        target_index, 
                        &front_tx.signature, 
                        &back_tx.signature,
                        &combined_intersection
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

        debug!("🎯 抢跑检测 - 目标交易过滤后账户数量: {}", target_accounts.len());

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
                if program_id == SYSTEM_PROGRAM_ID {
                    if self.is_small_transfer_instruction(instruction, &tx.transaction.message.account_keys) {
                        continue; // 跳过小额转账账户
                    }
                }

                for &acc_index in &instruction.accounts {
                    if let Some(account) = tx.transaction.message.account_keys.get(acc_index as usize) {
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
                let readonly_unsigned_start = message.account_keys.len() - num_readonly_unsigned_accounts;
                account_index >= unsigned_start && account_index < readonly_unsigned_start
            }
        } else {
            // 如果没有header信息，无法判断，默认认为都可写（保守处理）
            true
        }
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

    /// 计算三明治攻击中的用户损失
    /// 通过分析MEV攻击者的利润来估算用户损失
    fn calculate_sandwich_loss(
        &self,
        transactions: &[Transaction],
        target_index: usize,
        front_tx_sig: &str,
        back_tx_sig: &str,
        shared_accounts: &[String],
    ) -> Option<UserLoss> {
        info!("🧮 开始计算三明治攻击损失...");
        
        // 获取三笔交易
        let target_tx = &transactions[target_index];
        let front_tx = transactions.iter().find(|tx| tx.signature == front_tx_sig)?;
        let back_tx = transactions.iter().find(|tx| tx.signature == back_tx_sig)?;
        
        // 方法1: 分析攻击者的SOL余额变化 (通过Jito小费推断)
        if let Some(loss) = self.analyze_sol_balance_changes(front_tx, target_tx, back_tx) {
            info!("💡 使用SOL余额变化分析法计算损失");
            return Some(loss);
        }
        
        // 方法2: 分析共享账户的状态变化
        if let Some(loss) = self.analyze_shared_account_changes(
            front_tx, target_tx, back_tx, shared_accounts
        ) {
            info!("💡 使用共享账户状态变化分析法计算损失");
            return Some(loss);
        }
        
        // 方法3: 基础估算 (基于交易复杂度)
        let basic_loss = self.estimate_basic_loss(target_tx);
        info!("💡 使用基础估算法计算损失");
        Some(basic_loss)
    }
    
    /// 分析SOL余额变化来估算损失
    fn analyze_sol_balance_changes(
        &self,
        front_tx: &Transaction,
        target_tx: &Transaction,
        back_tx: &Transaction,
    ) -> Option<UserLoss> {
        // 查找攻击者账户 (在前后交易中都出现的签名账户)
        let front_signers: HashSet<&String> = front_tx.transaction.message.account_keys
            .iter().take(front_tx.transaction.message.header.as_ref()?.num_required_signatures as usize)
            .collect();
        let back_signers: HashSet<&String> = back_tx.transaction.message.account_keys
            .iter().take(back_tx.transaction.message.header.as_ref()?.num_required_signatures as usize)
            .collect();
        
        // 找到共同的签名者 (可能是攻击者)
        let common_signers: Vec<&String> = front_signers.intersection(&back_signers).cloned().collect();
        
        if !common_signers.is_empty() {
            // 分析前后交易中的SOL转账金额
            let front_sol_amount = self.extract_sol_transfer_amount(front_tx);
            let back_sol_amount = self.extract_sol_transfer_amount(back_tx);
            let target_sol_amount = self.extract_sol_transfer_amount(target_tx);
            
            info!("  前置交易SOL转账: {} lamports", front_sol_amount);
            info!("  目标交易SOL转账: {} lamports", target_sol_amount);
            info!("  后置交易SOL转账: {} lamports", back_sol_amount);
            
            // 估算MEV利润 = 后置交易收益 - 前置交易成本
            let mev_profit = back_sol_amount.saturating_sub(front_sol_amount);
            
            if mev_profit > 0 {
                // 用户损失通常是MEV利润的70-90%
                let estimated_loss = (mev_profit as f64 * 0.8) as u64;
                let loss_percentage = if target_sol_amount > 0 {
                    (estimated_loss as f64 / target_sol_amount as f64) * 100.0
                } else {
                    0.0
                };
                
                return Some(UserLoss {
                    estimated_loss_lamports: estimated_loss,
                    loss_percentage,
                    calculation_method: "SOL余额变化分析".to_string(),
                    mev_profit_lamports: mev_profit,
                });
            }
        }
        
        None
    }
    
    /// 分析共享账户状态变化
    fn analyze_shared_account_changes(
        &self,
        _front_tx: &Transaction,
        target_tx: &Transaction,
        _back_tx: &Transaction,
        shared_accounts: &[String],
    ) -> Option<UserLoss> {
        if shared_accounts.is_empty() {
            return None;
        }
        
        // 基于共享账户数量和交易复杂度估算
        let complexity_score = shared_accounts.len() * target_tx.transaction.message.instructions.len();
        let estimated_loss = (complexity_score as f64 * 50000.0) as u64; // 每个复杂度单位约0.05 SOL
        
        Some(UserLoss {
            estimated_loss_lamports: estimated_loss,
            loss_percentage: 2.0, // 假设2%的滑点损失
            calculation_method: "共享账户复杂度分析".to_string(),
            mev_profit_lamports: estimated_loss,
        })
    }
    
    /// 基础损失估算
    fn estimate_basic_loss(&self, target_tx: &Transaction) -> UserLoss {
        // 基于交易指令数量的基础估算
        let instruction_count = target_tx.transaction.message.instructions.len();
        let estimated_loss = (instruction_count as f64 * 100000.0) as u64; // 每个指令约0.1 SOL损失
        
        UserLoss {
            estimated_loss_lamports: estimated_loss,
            loss_percentage: 1.5, // 假设1.5%的基础损失
            calculation_method: "基础估算法".to_string(),
            mev_profit_lamports: estimated_loss,
        }
    }
    
    /// 提取交易中的SOL转账金额
    fn extract_sol_transfer_amount(&self, tx: &Transaction) -> u64 {
        let mut total_amount = 0u64;
        
        for instruction in &tx.transaction.message.instructions {
            // 检查是否为系统程序转账指令
            if let Some(program_id) = tx.transaction.message.account_keys.get(instruction.program_id_index as usize) {
                if program_id == SYSTEM_PROGRAM_ID {
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
                        
                        if amount > SMALL_TRANSFER_THRESHOLD {
                            total_amount += amount;
                        }
                    }
                }
            }
        }
        
        total_amount
    }
}
