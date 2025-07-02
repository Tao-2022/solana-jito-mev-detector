use crate::client::Transaction;
use std::collections::HashSet;

pub struct MevDetector;

pub struct SandwichDetails {
    pub front_tx: String,
    pub back_tx: String,
    pub profit_estimate: f64,
}

pub struct FrontrunDetails {
    pub frontrun_tx: String,
    pub victim_tx: String,
    pub time_difference_ms: i64,
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
            if let (Some(ft), Some(tt)) = (potential.block_time, target_tx.block_time) {
                let diff = tt - ft;
                if diff < 5 && self.has_similar_operations(potential, target_tx)
                    && self.targets_same_token_pair_simple(potential, target_tx) {
                    return Some(FrontrunDetails {
                        frontrun_tx: potential.signature.clone(),
                        victim_tx: target_tx.signature.clone(),
                        time_difference_ms: diff * 1000,
                    });
                }
            }
        }

        None
    }

    /// 判断两笔交易是否由同一个攻击者发起。
    ///
    /// # 参数
    /// - `tx1`: 第一笔交易。
    /// - `tx2`: 第二笔交易。
    ///
    /// # 返回
    /// 如果是同一个攻击者，返回`true`，否则返回`false`。
    fn is_same_attacker(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        tx1.transaction.message.account_keys.first() == tx2.transaction.message.account_keys.first()
    }

    /// 判断两笔交易是否针对相同的代币对进行操作。
    ///
    /// # 参数
    /// - `tx1`: 第一笔交易。
    /// - `tx2`: 第二笔交易。
    /// - `target`: 目标交易。
    ///
    /// # 返回
    /// 如果针对相同的代币对，返回`true`，否则返回`false`。
    fn targets_same_token_pair(&self, tx1: &Transaction, tx2: &Transaction, target: &Transaction) -> bool {
        let get_program_ids = |tx: &Transaction| -> HashSet<String> {
            tx.transaction.message.instructions.iter()
                .filter_map(|i| i.program_id.clone())
                .collect()
        };

        let tx1_programs = get_program_ids(tx1);
        let tx2_programs = get_program_ids(tx2);
        let target_programs = get_program_ids(target);

        const DEX_PROGRAMS: [&str; 3] = [
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium
            "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP", // Orca
            "22Y43yTVxuUkoRKdm9thyRhQ3SdgQS7c7kB6UNCiaczD", // Serum
        ];

        DEX_PROGRAMS.iter().any(|dex| {
            tx1_programs.contains(*dex)
                && tx2_programs.contains(*dex)
                && target_programs.contains(*dex)
        })
    }

    /// 简单判断两笔交易是否针对相同的代币对进行操作。
    ///
    /// # 参数
    /// - `tx1`: 第一笔交易。
    /// - `tx2`: 第二笔交易。
    ///
    /// # 返回
    /// 如果有共同的程序ID，返回`true`，否则返回`false`。
    fn targets_same_token_pair_simple(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        let tx1_programs: HashSet<String> = tx1.transaction.message.instructions.iter()
            .filter_map(|i| i.program_id.clone()).collect();
        let tx2_programs: HashSet<String> = tx2.transaction.message.instructions.iter()
            .filter_map(|i| i.program_id.clone()).collect();
        !tx1_programs.is_disjoint(&tx2_programs)
    }

    /// 判断两笔交易是否具有相反的操作（例如，一笔买入，一笔卖出）。
    ///
    /// # 参数
    /// - `tx1`: 第一笔交易。
    /// - `tx2`: 第二笔交易。
    ///
    /// # 返回
    /// 如果操作相反，返回`true`，否则返回`false`。
    fn has_opposite_operations(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        tx1.transaction.message.instructions.first().map(|i| &i.data)
            != tx2.transaction.message.instructions.first().map(|i| &i.data)
    }

    /// 判断两笔交易是否具有相似的操作（例如，相同的程序ID）。
    ///
    /// # 参数
    /// - `tx1`: 第一笔交易。
    /// - `tx2`: 第二笔交易。
    ///
    /// # 返回
    /// 如果操作相似，返回`true`，否则返回`false`。
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
    ///
    /// # 参数
    /// - `_front`: 前置交易。
    /// - `_back`: 后置交易。
    ///
    /// # 返回
    /// 估算的利润百分比。
    fn estimate_sandwich_profit(&self, _front: &Transaction, _back: &Transaction) -> f64 {
        0.01 // Placeholder
    }
}
