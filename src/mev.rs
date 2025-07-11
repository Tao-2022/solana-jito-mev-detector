use crate::client::Transaction;
use std::collections::HashSet;
use bs58;
use log::info;

pub struct MevDetector;

pub struct SandwichDetails {
    pub front_tx: String,
    pub back_tx: String,
    pub victim_loss_estimate: f64,  // 用户损失估算
}

pub struct FrontrunDetails {
    pub front_tx: String,
    pub victim_tx: String,
}

#[derive(Debug)]
pub struct JitoBundle {
    pub tip_tx_signature: String,
    pub tip_amount_lamports: u64,
    pub tip_account: String,
    // A Jito bundle is up to 5 transactions, with the tip tx being the last one.
    // This Vec contains the 4 transactions before the tip.
    pub bundle_transactions: Vec<Transaction>,
}

// 主要 DEX 程序 ID
const RAYDIUM_AMM_PROGRAM_ID: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
const RAYDIUM_CLMM_PROGRAM_ID: &str = "CAMMCzo5YL8w4VFF8KVHrK22GGUQzGdR1qJRXgKhpNzc";
const ORCA_WHIRLPOOLS_PROGRAM_ID: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
const ORCA_V1_PROGRAM_ID: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const SERUM_DEX_PROGRAM_ID: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const JUPITER_PROGRAM_ID: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

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
const ALLOWED_PROGRAMS_FOR_SIMPLE_TRANSFER: [&str; 2] = [SYSTEM_PROGRAM_ID, MEMO_PROGRAM_ID];

impl MevDetector {

    /// 检查交易是否为简单的转账（仅涉及系统程序或Memo程序）。
    pub fn is_simple_transfer(&self, tx: &Transaction) -> bool {
        tx.transaction.message.instructions.iter().all(|inst| {
            inst.program_id.as_ref().map_or(false, |id| {
                ALLOWED_PROGRAMS_FOR_SIMPLE_TRANSFER.contains(&id.as_str())
            })
        })
    }

    /// 检查目标交易前3笔和后4笔交易中是否有Jito小费地址
    pub fn check_jito_tip_in_nearby_transactions(&self, block_transactions: &[Transaction], target_index: usize) -> bool {
        // 获取前3笔交易
        let start_index = target_index.saturating_sub(3);
        // 获取后4笔交易
        let end_index = std::cmp::min(target_index + 5, block_transactions.len());
        
        for i in start_index..end_index {
            if i == target_index {
                continue; // 跳过目标交易本身
            }
            
            let tx = &block_transactions[i];
            // 检查交易的账户列表是否包含Jito小费地址
            for account in &tx.transaction.message.account_keys {
                if JITO_TIP_ACCOUNTS.contains(&account.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    /// 在一个区块的交易列表中，从给定的索引开始，寻找Jito小费交易并返回包含该捆绑包的详细信息。
    /// Jito捆绑包最多包含5笔交易，其中最后一笔是给Jito的小费交易。
    pub fn find_jito_tip_and_bundle(&self, block_transactions: &[Transaction], start_index: usize) -> Option<JitoBundle> {
        // 从目标交易开始，向后扫描区块寻找Jito小费
        for i in start_index..block_transactions.len() {
            let potential_tip_tx = &block_transactions[i];
            for instruction in &potential_tip_tx.transaction.message.instructions {
                if instruction.program_id.as_deref() == Some(SYSTEM_PROGRAM_ID) && instruction.accounts.len() >= 2 {
                    let receiver_index = instruction.accounts[1] as usize;
                    if let Some(receiver_account) = potential_tip_tx.transaction.message.account_keys.get(receiver_index) {
                        if JITO_TIP_ACCOUNTS.contains(&receiver_account.as_str()) {
                            if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
                                if data.len() == 12 && data[0..4] == [2, 0, 0, 0] {
                                    let amount = u64::from_le_bytes(data[4..12].try_into().unwrap());
                                    
                                    // 找到了小费交易，现在构建捆绑包 (小费交易前的最多4笔交易)
                                    let bundle_start_index = i.saturating_sub(4);
                                    let bundle_transactions = block_transactions[bundle_start_index..i].to_vec();

                                    return Some(JitoBundle {
                                        tip_tx_signature: potential_tip_tx.signature.clone(),
                                        tip_amount_lamports: amount,
                                        tip_account: receiver_account.clone(),
                                        bundle_transactions,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// 检测交易列表中是否存在三明治攻击 - 改进版本
    pub fn detect_sandwich_attack(&self, transactions: &[Transaction], target_signature: &str) -> Option<SandwichDetails> {
        let target_index = transactions.iter().position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        // 检查目标交易是否是DEX交易
        if !self.is_dex_transaction(target_tx) {
            return None;
        }

        // 获取目标交易的代币对信息
        let target_tokens = self.extract_token_accounts(target_tx);
        if target_tokens.len() < 2 {
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

                // 检查是否都是DEX交易
                if !self.is_dex_transaction(front_tx) || !self.is_dex_transaction(back_tx) {
                    continue;
                }

                // 检查是否涉及相同的代币对
                if !self.involves_same_token_pair(front_tx, back_tx, target_tx) {
                    continue;
                }

                // 检查是否有相反的操作（买入->卖出）
                if !self.has_opposite_operations_enhanced(front_tx, back_tx, target_tx) {
                    continue;
                }

                // 计算用户潜在损失
                let victim_loss = self.calculate_victim_loss(front_tx, back_tx, target_tx);
                if victim_loss < MIN_LOSS_THRESHOLD {
                    continue;
                }

                info!("检测到三明治攻击模式，预估用户损失: {:.6} SOL", victim_loss);
                
                return Some(SandwichDetails {
                    front_tx: front_tx.signature.clone(),
                    back_tx: back_tx.signature.clone(),
                    victim_loss_estimate: victim_loss,
                });
            }
        }

        None
    }

    /// 检查交易是否为DEX交易
    fn is_dex_transaction(&self, tx: &Transaction) -> bool {
        const DEX_PROGRAMS: [&str; 6] = [
            RAYDIUM_AMM_PROGRAM_ID,
            RAYDIUM_CLMM_PROGRAM_ID,
            ORCA_WHIRLPOOLS_PROGRAM_ID,
            ORCA_V1_PROGRAM_ID,
            SERUM_DEX_PROGRAM_ID,
            JUPITER_PROGRAM_ID,
        ];

        tx.transaction.message.instructions.iter().any(|inst| {
            inst.program_id.as_ref()
                .map(|id| DEX_PROGRAMS.contains(&id.as_str()))
                .unwrap_or(false)
        })
    }

    /// 提取交易中涉及的代币账户
    fn extract_token_accounts(&self, tx: &Transaction) -> HashSet<String> {
        let mut token_accounts = HashSet::new();
        
        // 获取所有非系统程序的账户
        for instruction in &tx.transaction.message.instructions {
            if let Some(program_id) = &instruction.program_id {
                if program_id != SYSTEM_PROGRAM_ID {
                    for &acc_index in &instruction.accounts {
                        if let Some(account) = tx.transaction.message.account_keys.get(acc_index as usize) {
                            token_accounts.insert(account.clone());
                        }
                    }
                }
            }
        }
        
        token_accounts
    }

    /// 检查三笔交易是否涉及相同的代币对
    fn involves_same_token_pair(&self, front_tx: &Transaction, back_tx: &Transaction, target_tx: &Transaction) -> bool {
        let front_tokens = self.extract_token_accounts(front_tx);
        let back_tokens = self.extract_token_accounts(back_tx);
        let target_tokens = self.extract_token_accounts(target_tx);

        // 检查三笔交易是否有足够的共同代币账户
        let common_front_target: HashSet<_> = front_tokens.intersection(&target_tokens).collect();
        let common_back_target: HashSet<_> = back_tokens.intersection(&target_tokens).collect();
        let common_all: HashSet<_> = common_front_target.intersection(&common_back_target).collect();

        common_all.len() >= MIN_SHARED_ACCOUNTS
    }

    /// 增强版检查是否有相反操作
    fn has_opposite_operations_enhanced(&self, front_tx: &Transaction, back_tx: &Transaction, target_tx: &Transaction) -> bool {
        // 获取交易的操作类型（通过指令数据的前8字节判断）
        let get_operation_type = |tx: &Transaction| -> Option<[u8; 8]> {
            tx.transaction.message.instructions.first().and_then(|inst| {
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
    fn calculate_victim_loss(&self, front_tx: &Transaction, back_tx: &Transaction, target_tx: &Transaction) -> f64 {
        // 简化的损失计算，基于交易的复杂度和涉及的代币数量
        // 在三明治攻击中，攻击者的利润就是用户的损失
        let front_accounts = self.extract_token_accounts(front_tx);
        let back_accounts = self.extract_token_accounts(back_tx);
        let target_accounts = self.extract_token_accounts(target_tx);

        let complexity_factor = (front_accounts.len() + back_accounts.len() + target_accounts.len()) as f64 / 10.0;
        let base_loss = 0.005; // 基础损失估算
        
        // 根据交易复杂度调整损失估算
        // 更复杂的交易通常意味着更大的滑点和损失
        base_loss * complexity_factor.min(3.0)
    }

    /// 检测交易列表中是否存在抢跑攻击 - 改进版本
    pub fn detect_frontrun_attack(&self, transactions: &[Transaction], target_signature: &str) -> Option<FrontrunDetails> {
        let target_index = transactions.iter().position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        // 检查目标交易是否是DEX交易
        if !self.is_dex_transaction(target_tx) {
            return None;
        }

        let target_tokens = self.extract_token_accounts(target_tx);
        if target_tokens.len() < 2 {
            return None;
        }

        // 在目标交易前寻找潜在的抢跑交易
        for i in (0..target_index).rev() {
            let potential_frontrun = &transactions[i];

            // 检查是否是DEX交易
            if !self.is_dex_transaction(potential_frontrun) {
                continue;
            }

            // 检查是否在同一个slot（时间窗口）
            if potential_frontrun.slot != target_tx.slot {
                continue;
            }

            // 检查是否涉及相同的代币对
            if !self.involves_same_token_pair_frontrun(potential_frontrun, target_tx) {
                continue;
            }

            // 检查是否有相似的操作（相同方向的交易）
            if !self.has_similar_operations_enhanced(potential_frontrun, target_tx) {
                continue;
            }

            // 检查交易金额是否显著大于目标交易（典型的抢跑特征）
            if !self.is_significantly_larger_transaction(potential_frontrun, target_tx) {
                continue;
            }

            // 检查gas费用是否异常高（抢跑者通常愿意支付更高gas费）
            if !self.has_higher_priority_fee(potential_frontrun, target_tx) {
                continue;
            }

            info!("检测到抢跑攻击模式，抢跑交易比目标交易优先执行");
            
            return Some(FrontrunDetails {
                front_tx: potential_frontrun.signature.clone(),
                victim_tx: target_tx.signature.clone(),
            });
        }

        None
    }

    /// 检查两笔交易是否涉及相同的代币对（抢跑版本）
    fn involves_same_token_pair_frontrun(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        let tokens1 = self.extract_token_accounts(tx1);
        let tokens2 = self.extract_token_accounts(tx2);
        
        // 检查是否有至少2个共同的代币账户
        let common_tokens: HashSet<_> = tokens1.intersection(&tokens2).collect();
        common_tokens.len() >= 2
    }

    /// 增强版检查是否有相似操作（抢跑通常是同方向操作）
    fn has_similar_operations_enhanced(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        // 检查是否使用相同的DEX程序
        let tx1_dex_programs = self.get_dex_programs(tx1);
        let tx2_dex_programs = self.get_dex_programs(tx2);
        
        // 如果使用相同的DEX程序，则可能是相似操作
        !tx1_dex_programs.is_disjoint(&tx2_dex_programs)
    }

    /// 获取交易中使用的DEX程序
    fn get_dex_programs(&self, tx: &Transaction) -> HashSet<String> {
        const DEX_PROGRAMS: [&str; 6] = [
            RAYDIUM_AMM_PROGRAM_ID,
            RAYDIUM_CLMM_PROGRAM_ID,
            ORCA_WHIRLPOOLS_PROGRAM_ID,
            ORCA_V1_PROGRAM_ID,
            SERUM_DEX_PROGRAM_ID,
            JUPITER_PROGRAM_ID,
        ];

        tx.transaction.message.instructions.iter()
            .filter_map(|inst| inst.program_id.as_ref())
            .filter(|id| DEX_PROGRAMS.contains(&id.as_str()))
            .cloned()
            .collect()
    }

    /// 检查交易是否显著大于目标交易（基于账户数量和指令复杂度）
    fn is_significantly_larger_transaction(&self, frontrun_tx: &Transaction, target_tx: &Transaction) -> bool {
        let frontrun_accounts = frontrun_tx.transaction.message.account_keys.len();
        let target_accounts = target_tx.transaction.message.account_keys.len();
        
        let frontrun_instructions = frontrun_tx.transaction.message.instructions.len();
        let target_instructions = target_tx.transaction.message.instructions.len();

        // 抢跑交易通常账户数量或指令数量更多（更复杂的操作）
        frontrun_accounts > target_accounts || frontrun_instructions > target_instructions
    }

    /// 检查是否有更高的优先级费用（简化版本）
    fn has_higher_priority_fee(&self, frontrun_tx: &Transaction, target_tx: &Transaction) -> bool {
        // 由于无法直接获取priority fee，我们通过交易复杂度来推断
        // 抢跑者通常会使用更复杂的路由来获得更好的价格
        let frontrun_complexity = self.calculate_transaction_complexity(frontrun_tx);
        let target_complexity = self.calculate_transaction_complexity(target_tx);
        
        frontrun_complexity > target_complexity
    }

    /// 计算交易复杂度
    fn calculate_transaction_complexity(&self, tx: &Transaction) -> u32 {
        let account_count = tx.transaction.message.account_keys.len() as u32;
        let instruction_count = tx.transaction.message.instructions.len() as u32;
        let total_data_size: u32 = tx.transaction.message.instructions.iter()
            .map(|inst| inst.data.len() as u32)
            .sum();

        account_count + instruction_count * 2 + total_data_size / 100
    }

    fn is_same_attacker(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        tx1.transaction.message.account_keys.first() == tx2.transaction.message.account_keys.first()
    }
}
