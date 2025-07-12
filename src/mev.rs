use crate::client::Transaction;
use bs58;
use log::{debug, error, info, warn};
use std::collections::HashSet;

pub struct MevDetector;

pub struct SandwichDetails {
    pub front_tx: String,
    pub back_tx: String,
    pub victim_loss_estimate: f64, // 用户损失估算
}

pub struct FrontrunDetails {
    pub front_tx: String,
    pub victim_tx: String,
}

// 主要 DEX 程序 ID
const RAYDIUM_AMM_PROGRAM_ID: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
const RAYDIUM_CLMM_PROGRAM_ID: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUQzGdR1qJRXgKhpNzc";
const ORCA_WHIRLPOOLS_PROGRAM_ID: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
const ORCA_V1_PROGRAM_ID: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const SERUM_DEX_PROGRAM_ID: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const JUPITER_PROGRAM_ID: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const PUMP_FUN_PROGRAM_ID: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";

// 三明治攻击检测相关常量
const MIN_SHARED_ACCOUNTS: usize = 3;
const MAX_PRICE_IMPACT_THRESHOLD: f64 = 0.05; // 5%价格影响阈值
const MIN_LOSS_THRESHOLD: f64 = 0.001; // 最小损失阈值 (SOL)
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

    /// 检测交易列表中是否存在三明治攻击 - 基于账户比较的改进版本
    pub fn detect_sandwich_attack(
        &self,
        transactions: &[Transaction],
        target_signature: &str,
    ) -> Option<SandwichDetails> {
        let target_index = transactions
            .iter()
            .position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        // 检查目标交易是否是交易类型（使用更宽松的检测）
        if !self.is_dex_transaction(target_tx) {
            return None;
        }

        // 获取目标交易的代币账户信息
        let target_accounts = self.extract_all_accounts(target_tx);
        if target_accounts.len() < 4 {
            // 降低最小账户要求
            return None;
        }

        // 在目标交易前后寻找潜在的三明治攻击
        for front_idx in 0..target_index {
            for back_idx in (target_index + 1)..transactions.len() {
                let front_tx = &transactions[front_idx];
                let back_tx = &transactions[back_idx];

                // 检查是否是同一个攻击者
                if !self.is_same_attacker(front_tx, back_tx) {
                    continue;
                }

                // 检查是否都是交易类型
                if !self.is_dex_transaction(front_tx) || !self.is_dex_transaction(back_tx) {
                    continue;
                }

                // 使用更宽松的账户重叠检测
                if !self.has_significant_account_overlap(front_tx, back_tx, target_tx) {
                    continue;
                }

                // 检查时间顺序和交易模式
                if !self.matches_sandwich_pattern(front_tx, back_tx, target_tx) {
                    continue;
                }

                // 计算用户潜在损失
                let victim_loss = self.calculate_victim_loss(front_tx, back_tx, target_tx);
                if victim_loss < MIN_LOSS_THRESHOLD {
                    continue;
                }

                info!(
                    "检测到三明治攻击模式（基于账户分析），预估用户损失: {:.6} SOL",
                    victim_loss
                );

                return Some(SandwichDetails {
                    front_tx: front_tx.signature.clone(),
                    back_tx: back_tx.signature.clone(),
                    victim_loss_estimate: victim_loss,
                });
            }
        }

        None
    }

    /// 提取交易中的所有账户（不仅仅是token账户）
    fn extract_all_accounts(&self, tx: &Transaction) -> HashSet<String> {
        let mut all_accounts = HashSet::new();

        // 获取所有账户（包括指令中引用的账户）
        for instruction in &tx.transaction.message.instructions {
            for &acc_index in &instruction.accounts {
                if let Some(account) = tx.transaction.message.account_keys.get(acc_index as usize) {
                    all_accounts.insert(account.clone());
                }
            }
        }

        all_accounts
    }

    /// 检查三笔交易是否有显著的账户重叠
    fn has_significant_account_overlap(
        &self,
        front_tx: &Transaction,
        back_tx: &Transaction,
        target_tx: &Transaction,
    ) -> bool {
        let front_accounts = self.extract_all_accounts(front_tx);
        let back_accounts = self.extract_all_accounts(back_tx);
        let target_accounts = self.extract_all_accounts(target_tx);

        // 计算三方交易的账户重叠
        let front_target_overlap: HashSet<_> =
            front_accounts.intersection(&target_accounts).collect();
        let back_target_overlap: HashSet<_> =
            back_accounts.intersection(&target_accounts).collect();
        let all_three_overlap: HashSet<_> = front_target_overlap
            .intersection(&back_target_overlap)
            .collect();

        // 降低要求，至少有2个共同账户就可能是三明治攻击
        let min_overlap = 2;

        // 同时检查前后交易之间的账户重叠
        let front_back_overlap: HashSet<_> = front_accounts.intersection(&back_accounts).collect();

        all_three_overlap.len() >= min_overlap || front_back_overlap.len() >= min_overlap
    }

    /// 检查是否符合三明治攻击的模式
    fn matches_sandwich_pattern(
        &self,
        front_tx: &Transaction,
        back_tx: &Transaction,
        target_tx: &Transaction,
    ) -> bool {
        // 检查交易复杂度模式
        let front_complexity = self.calculate_transaction_complexity(front_tx);
        let back_complexity = self.calculate_transaction_complexity(back_tx);
        let target_complexity = self.calculate_transaction_complexity(target_tx);

        // 三明治攻击中，前后交易通常比目标交易更复杂
        let complexity_pattern = (front_complexity > target_complexity * 80 / 100)
            || (back_complexity > target_complexity * 80 / 100);

        // 检查账户数量模式
        let front_accounts = front_tx.transaction.message.account_keys.len();
        let back_accounts = back_tx.transaction.message.account_keys.len();
        let target_accounts = target_tx.transaction.message.account_keys.len();

        // 攻击者交易通常账户数量相似
        let similar_complexity = (front_accounts as i32 - back_accounts as i32).abs() <= 3;

        complexity_pattern && similar_complexity
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
        let instruction_count = tx.transaction.message.instructions.len();

        // swap交易通常涉及至少6个账户（用户钱包、token账户、池子账户、程序等）
        let has_multiple_accounts = account_count >= 6;

        // 检查是否有非系统程序的指令
        let has_non_system_instructions = tx.transaction.message.instructions.iter().any(|inst| {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(inst.program_id_index as usize)
            {
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

    /// 提取交易中涉及的代币账户
    fn extract_token_accounts(&self, tx: &Transaction) -> HashSet<String> {
        let mut token_accounts = HashSet::new();

        // 获取所有非系统程序的账户
        for instruction in &tx.transaction.message.instructions {
            if let Some(program_id) = tx
                .transaction
                .message
                .account_keys
                .get(instruction.program_id_index as usize)
            {
                if program_id != SYSTEM_PROGRAM_ID {
                    for &acc_index in &instruction.accounts {
                        if let Some(account) =
                            tx.transaction.message.account_keys.get(acc_index as usize)
                        {
                            token_accounts.insert(account.clone());
                        }
                    }
                }
            }
        }

        token_accounts
    }

    /// 检查三笔交易是否涉及相同的代币对
    fn involves_same_token_pair(
        &self,
        front_tx: &Transaction,
        back_tx: &Transaction,
        target_tx: &Transaction,
    ) -> bool {
        let front_tokens = self.extract_token_accounts(front_tx);
        let back_tokens = self.extract_token_accounts(back_tx);
        let target_tokens = self.extract_token_accounts(target_tx);

        // 检查三笔交易是否有足够的共同代币账户
        let common_front_target: HashSet<_> = front_tokens.intersection(&target_tokens).collect();
        let common_back_target: HashSet<_> = back_tokens.intersection(&target_tokens).collect();
        let common_all: HashSet<_> = common_front_target
            .intersection(&common_back_target)
            .collect();

        common_all.len() >= MIN_SHARED_ACCOUNTS
    }

    /// 增强版检查是否有相反操作
    fn has_opposite_operations_enhanced(
        &self,
        front_tx: &Transaction,
        back_tx: &Transaction,
        target_tx: &Transaction,
    ) -> bool {
        // 获取交易的操作类型（通过指令数据的前8字节判断）
        let get_operation_type = |tx: &Transaction| -> Option<[u8; 8]> {
            tx.transaction
                .message
                .instructions
                .first()
                .and_then(|inst| {
                    if let Ok(data) = bs58::decode(&inst.data).into_vec() {
                        if data.len() >= 8 {
                            let mut op_type = [0u8; 8];
                            op_type.copy_from_slice(&data[0..8]);
                            Some(op_type)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
        };

        let front_op = get_operation_type(front_tx);
        let back_op = get_operation_type(back_tx);
        let target_op = get_operation_type(target_tx);

        // 检查前置和后置交易是否有不同的操作类型
        match (front_op, back_op, target_op) {
            (Some(front), Some(back), Some(_target)) => {
                // 如果前置和后置操作不同，且与目标交易的操作相关，则可能是三明治攻击
                front != back
            }
            _ => false,
        }
    }

    /// 计算用户在三明治攻击中的损失
    fn calculate_victim_loss(
        &self,
        front_tx: &Transaction,
        back_tx: &Transaction,
        target_tx: &Transaction,
    ) -> f64 {
        // 简化的损失计算，基于交易的复杂度和涉及的代币数量
        // 在三明治攻击中，攻击者的利润就是用户的损失
        let front_accounts = self.extract_token_accounts(front_tx);
        let back_accounts = self.extract_token_accounts(back_tx);
        let target_accounts = self.extract_token_accounts(target_tx);

        let complexity_factor =
            (front_accounts.len() + back_accounts.len() + target_accounts.len()) as f64 / 10.0;
        let base_loss = 0.005; // 基础损失估算

        // 根据交易复杂度调整损失估算
        // 更复杂的交易通常意味着更大的滑点和损失
        base_loss * complexity_factor.min(3.0)
    }

    /// 检测交易列表中是否存在抢跑攻击 - 基于账户比较的改进版本
    pub fn detect_frontrun_attack(
        &self,
        transactions: &[Transaction],
        target_signature: &str,
    ) -> Option<FrontrunDetails> {
        let target_index = transactions
            .iter()
            .position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        // 检查目标交易是否是交易类型（使用更宽松的检测）
        if !self.is_dex_transaction(target_tx) {
            return None;
        }

        let target_accounts = self.extract_all_accounts(target_tx);
        if target_accounts.len() < 4 {
            return None;
        }

        // 在目标交易前寻找潜在的抢跑交易
        for i in (0..target_index).rev() {
            let potential_frontrun = &transactions[i];

            // 检查是否是交易类型
            if !self.is_dex_transaction(potential_frontrun) {
                continue;
            }

            // 检查是否在同一个slot（时间窗口）
            if potential_frontrun.slot != target_tx.slot {
                continue;
            }

            // 使用账户重叠检测相同的代币对
            if !self.has_account_overlap_for_frontrun(potential_frontrun, target_tx) {
                continue;
            }

            // 检查是否有相似的交易模式
            if !self.has_similar_transaction_pattern(potential_frontrun, target_tx) {
                continue;
            }

            // 检查是否符合抢跑特征
            if !self.matches_frontrun_characteristics(potential_frontrun, target_tx) {
                continue;
            }

            info!("检测到抢跑攻击模式（基于账户分析），抢跑交易比目标交易优先执行");

            return Some(FrontrunDetails {
                front_tx: potential_frontrun.signature.clone(),
                victim_tx: target_tx.signature.clone(),
            });
        }

        None
    }

    /// 检查两笔交易是否有账户重叠（抢跑版本）
    fn has_account_overlap_for_frontrun(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        let accounts1 = self.extract_all_accounts(tx1);
        let accounts2 = self.extract_all_accounts(tx2);

        // 检查是否有至少2个共同的账户
        let common_accounts: HashSet<_> = accounts1.intersection(&accounts2).collect();
        common_accounts.len() >= 2
    }

    /// 检查是否有相似的交易模式
    fn has_similar_transaction_pattern(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        // 比较交易复杂度
        let complexity1 = self.calculate_transaction_complexity(tx1);
        let complexity2 = self.calculate_transaction_complexity(tx2);

        // 抢跑交易通常复杂度相似或更高
        let complexity_ratio = if complexity2 > 0 {
            complexity1 as f64 / complexity2 as f64
        } else {
            1.0
        };

        // 复杂度比率在合理范围内
        complexity_ratio >= 0.8 && complexity_ratio <= 2.0
    }

    /// 检查是否符合抢跑特征
    fn matches_frontrun_characteristics(
        &self,
        frontrun_tx: &Transaction,
        target_tx: &Transaction,
    ) -> bool {
        // 检查账户数量
        let frontrun_accounts = frontrun_tx.transaction.message.account_keys.len();
        let target_accounts = target_tx.transaction.message.account_keys.len();

        // 检查指令数量
        let frontrun_instructions = frontrun_tx.transaction.message.instructions.len();
        let target_instructions = target_tx.transaction.message.instructions.len();

        // 抢跑交易通常有以下特征之一：
        // 1. 更多的账户（更复杂的路由）
        // 2. 更多的指令（更复杂的操作）
        // 3. 相似的账户数量但更高的复杂度

        let more_accounts = frontrun_accounts > target_accounts;
        let more_instructions = frontrun_instructions > target_instructions;
        let similar_size_but_complex = (frontrun_accounts as i32 - target_accounts as i32).abs()
            <= 2
            && self.calculate_transaction_complexity(frontrun_tx)
                > self.calculate_transaction_complexity(target_tx);

        more_accounts || more_instructions || similar_size_but_complex
    }

    /// 计算交易复杂度
    fn calculate_transaction_complexity(&self, tx: &Transaction) -> u32 {
        let account_count = tx.transaction.message.account_keys.len() as u32;
        let instruction_count = tx.transaction.message.instructions.len() as u32;
        let total_data_size: u32 = tx
            .transaction
            .message
            .instructions
            .iter()
            .map(|inst| inst.data.len() as u32)
            .sum();

        account_count + instruction_count * 2 + total_data_size / 100
    }

    fn is_same_attacker(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        tx1.transaction.message.account_keys.first() == tx2.transaction.message.account_keys.first()
    }
}
