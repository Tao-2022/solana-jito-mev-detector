use crate::client::Transaction;
use std::collections::HashSet;

pub struct MevDetector;

pub struct SandwichDetails {
    pub front_tx: String,
    pub back_tx: String,
    pub profit_estimate: f64,
}

pub struct FrontrunDetails {
    pub front_tx: String,
    pub victim_tx: String,
}

impl MevDetector {
    /// 检测交易列表中是否存在三明治攻击。
    ///
    /// # 参数
    /// - `transactions`: 包含相关交易的向量。
    /// - `target_signature`: 目标交易的签名。
    ///
    /// # 返回
    /// 如果检测到三明治攻击，返回`Some(SandwichDetails)`，否则返回`None`。
    pub fn detect_sandwich_attack(&self, transactions: &[Transaction], target_signature: &str) -> Option<SandwichDetails> {
        let target_index = transactions.iter().position(|tx| tx.signature == target_signature)?;

        for i in 0..target_index {
            for j in (target_index + 1)..transactions.len() {
                let front_tx = &transactions[i];
                let back_tx = &transactions[j];

                if self.is_same_attacker(front_tx, back_tx)
                    && self.targets_same_token_pair(front_tx, back_tx, &transactions[target_index])
                    && self.has_opposite_operations(front_tx, back_tx)
                {
                    return Some(SandwichDetails {
                        front_tx: front_tx.signature.clone(),
                        back_tx: back_tx.signature.clone(),
                        profit_estimate: self.estimate_sandwich_profit(front_tx, back_tx),
                    });
                }
            }
        }

        None
    }

    /// 检测交易列表中是否存在抢跑攻击。
    ///
    /// # 参数
    /// - `transactions`: 包含相关交易的向量。
    /// - `target_signature`: 目标交易的签名。
    ///
    /// # 返回
    /// 如果检测到抢跑攻击，返回`Some(FrontrunDetails)`，否则返回`None`。
    pub fn detect_frontrun_attack(&self, transactions: &[Transaction], target_signature: &str) -> Option<FrontrunDetails> {
        let target_index = transactions.iter().position(|tx| tx.signature == target_signature)?;
        let target_tx = &transactions[target_index];

        for i in (0..target_index).rev() {
            let potential = &transactions[i];

            // 主要的抢跑检测逻辑：攻击者和受害者的交易在同一个区块（slot）中。
            // 由于交易列表是按区块中的顺序排列的，任何在目标交易之前的交易都是潜在的抢跑。
            if potential.slot == target_tx.slot
                && self.has_similar_operations(potential, target_tx)
                && self.targets_same_token_pair_simple(potential, target_tx)
            {
                return Some(FrontrunDetails {
                    front_tx: potential.signature.clone(),
                    victim_tx: target_tx.signature.clone(),
                });
            }
        }

        None
    }

    /// 判断两笔交易是否由同一个攻击者发起。
    fn is_same_attacker(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        tx1.transaction.message.account_keys.first() == tx2.transaction.message.account_keys.first()
    }

    /// 通过分析共享的DEX程序和账户，判断三笔交易是否针对相同的代币对。
    /// 这是检测三明治攻击的核心逻辑。
    fn targets_same_token_pair(&self, tx1: &Transaction, tx2: &Transaction, target: &Transaction) -> bool {
        const MIN_SHARED_ACCOUNTS: usize = 2; // 至少需要共享的账户数量（例如一个代币对的两个账户）

        let get_instruction_accounts = |tx: &Transaction| -> (HashSet<String>, HashSet<String>) {
            let mut programs = HashSet::new();
            let mut accounts = HashSet::new();
            for instruction in &tx.transaction.message.instructions {
                if let Some(prog_id) = &instruction.program_id {
                    programs.insert(prog_id.clone());
                }
                // instruction.accounts 是账户索引，我们需要从顶层 account_keys 获取实际地址
                for &acc_index in &instruction.accounts {
                    if let Some(key) = tx.transaction.message.account_keys.get(acc_index as usize) {
                        accounts.insert(key.clone());
                    }
                }
            }
            (programs, accounts)
        };

        let (tx1_programs, tx1_accounts) = get_instruction_accounts(tx1);
        let (tx2_programs, tx2_accounts) = get_instruction_accounts(tx2);
        let (target_programs, target_accounts) = get_instruction_accounts(target);

        // 1. 检查是否存在一个共同的DEX程序
        let common_programs: Vec<_> = tx1_programs
            .intersection(&target_programs)
            .cloned()
            .collect();
        if common_programs.is_empty() || !tx2_programs.contains(common_programs[0].as_str()) {
            return false;
        }

        // 2. 检查是否共享了足够多的账户（这是更强的信号）
        let common_accounts_target_tx1: HashSet<_> = target_accounts.intersection(&tx1_accounts).collect();
        let common_accounts_target_tx2: HashSet<_> = target_accounts.intersection(&tx2_accounts).collect();

        // 攻击者的两笔交易也必须共享这些从受害者那里来的账户
        let final_common_accounts: HashSet<_> = common_accounts_target_tx1
            .intersection(&common_accounts_target_tx2)
            .collect();

        final_common_accounts.len() >= MIN_SHARED_ACCOUNTS
    }

    /// 简单判断两笔交易是否针对相同的代币对进行操作。
    fn targets_same_token_pair_simple(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        let tx1_programs: HashSet<String> = tx1.transaction.message.instructions.iter()
            .filter_map(|i| i.program_id.clone()).collect();
        let tx2_programs: HashSet<String> = tx2.transaction.message.instructions.iter()
            .filter_map(|i| i.program_id.clone()).collect();
        !tx1_programs.is_disjoint(&tx2_programs)
    }

    /// 判断两笔交易是否具有相反的操作（例如，一笔买入，一笔卖出）。
    fn has_opposite_operations(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        tx1.transaction.message.instructions.first().map(|i| &i.data)
            != tx2.transaction.message.instructions.first().map(|i| &i.data)
    }

    /// 判断两笔交易是否具有相似的操作（例如，相同的程序ID）。
    fn has_similar_operations(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        match (
            tx1.transaction.message.instructions.first(),
            tx2.transaction.message.instructions.first()
        ) {
            (Some(i1), Some(i2)) => i1.program_id == i2.program_id,
            _ => false,
        }
    }

    /// 估算三明治攻击的利润。
    fn estimate_sandwich_profit(&self, _front: &Transaction, _back: &Transaction) -> f64 {
        0.01 // Placeholder
    }
}
