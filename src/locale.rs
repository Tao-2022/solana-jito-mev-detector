use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum Language {
    #[serde(rename = "en")]
    English,
    #[serde(rename = "zh")]
    Chinese,
}

impl Default for Language {
    fn default() -> Self {
        Language::English
    }
}

// A single struct to hold the selected language
#[derive(Clone)]
pub struct Locale {
    pub lang: Language,
}

impl Locale {
    pub fn new(lang: Language) -> Self {
        Self { lang }
    }

    // --- Main Messages ---

    pub fn starting(&self) -> &'static str {
        match self.lang {
            Language::English => "Starting Solana MEV Detector...",
            Language::Chinese => "Solana MEV 检测器启动...",
        }
    }

    pub fn title(&self) -> &'static str {
        match self.lang {
            Language::English => "🔍 Solana MEV Detector v0.2.0",
            Language::Chinese => "🔍 Solana MEV 检测器 v0.2.0",
        }
    }
    
    pub fn auto_detect_start(&self) -> &'static str {
        match self.lang {
            Language::English => "🤖 Found {} preset transaction hashes in config, starting auto-detection...",
            Language::Chinese => "🤖 检测到配置中有 {} 个预设的交易哈希，开始自动检测...",
        }
    }

    pub fn auto_detect_progress(&self) -> &'static str {
        match self.lang {
            Language::English => "🔄 Auto-detecting [{}/{}]: {}",
            Language::Chinese => "🔄 自动检测 [{}/{}]: {}",
        }
    }

    pub fn auto_detect_done(&self) -> &'static str {
        match self.lang {
            Language::English => "✅ Auto-detection complete!",
            Language::Chinese => "✅ 自动检测完成！",
        }
    }

    pub fn all_auto_detect_done(&self) -> &'static str {
        match self.lang {
            Language::English => "🎉 All preset transaction hashes have been processed!",
            Language::Chinese => "🎉 所有预设交易哈希检测完成！",
        }
    }

    pub fn prompt(&self) -> &'static str {
        match self.lang {
            Language::English => "
Please enter a Solana transaction hash (or 'exit'/'quit' to close):",
            Language::Chinese => "
请输入Solana交易哈希 (输入 'exit' 或 'quit' 退出):",
        }
    }

    pub fn exiting(&self) -> &'static str {
        match self.lang {
            Language::English => "
👋 Exiting program. Thanks for using!",
            Language::Chinese => "
👋 程序退出，感谢使用！",
        }
    }

    pub fn analyzing(&self) -> &'static str {
        match self.lang {
            Language::English => "🔄 Analyzing transaction:",
            Language::Chinese => "🔄 正在分析交易:",
        }
    }

    pub fn analysis_complete(&self) -> &'static str {
        match self.lang {
            Language::English => "✅ Analysis complete!",
            Language::Chinese => "✅ 分析完成！",
        }
    }

    pub fn analysis_failed(&self) -> &'static str {
        match self.lang {
            Language::English => "❌ Analysis failed: {}",
            Language::Chinese => "❌ 分析失败: {}",
        }
    }

    pub fn reading_input_failed(&self) -> &'static str {
        match self.lang {
            Language::English => "Failed to read input: {}",
            Language::Chinese => "读取输入失败: {}",
        }
    }

    pub fn get_tx_failed(&self) -> &'static str {
        match self.lang {
            Language::English => "Failed to get target transaction: {}",
            Language::Chinese => "获取目标交易失败: {}",
        }
    }

    pub fn get_tx_success(&self) -> &'static str {
        match self.lang {
            Language::English => "Successfully retrieved target transaction info, block: ",
            Language::Chinese => "获取目标交易信息成功，区块: ",
        }
    }

    pub fn simple_transfer(&self) -> &'static str {
        match self.lang {
            Language::English => "✅ This is a simple transfer, not a swap. No MEV risk detected.",
            Language::Chinese => "✅ 该交易为简单转账，不涉及Swap，无MEV风险。",
        }
    }

    pub fn swap_detected(&self) -> &'static str {
        match self.lang {
            Language::English => "🔍 This transaction involves a Swap/DEX, starting MEV risk analysis...",
            Language::Chinese => "🔍 该交易涉及Swap/DEX，开始MEV风险分析...",
        }
    }

    pub fn get_nearby_failed(&self) -> &'static str {
        match self.lang {
            Language::English => "Failed to get nearby transactions: {}",
            Language::Chinese => "获取周围交易信息失败: {}",
        }
    }

    pub fn rpc_suggestion(&self) -> &'static str {
        match self.lang {
            Language::English => "💡 Try changing the rpc_url in config.toml to resolve this.",
            Language::Chinese => "💡 修改config.toml中的rpc_url或许可以解决问题",
        }
    }

    pub fn analyzing_nearby(&self) -> &'static str {
        match self.lang {
            Language::English => "📊 Retrieved {} nearby transactions, starting analysis...",
            Language::Chinese => "📊 获取到周围{}笔交易，开始分析...",
        }
    }

    pub fn jito_bundle_detected(&self) -> &'static str {
        match self.lang {
            Language::English => "🎯 Jito bundle detected, analyzing for MEV attack...",
            Language::Chinese => "🎯 检测到Jito捆绑包交易，正在分析MEV攻击...",
        }
    }

    pub fn tip_location(&self) -> &'static str {
        match self.lang {
            Language::English => "📍 Jito tip location: {} the target transaction",
            Language::Chinese => "📍 Jito小费位置: 目标交易{}",
        }
    }

    pub fn tip_location_before(&self) -> &'static str {
        match self.lang {
            Language::English => "before",
            Language::Chinese => "前方",
        }
    }

    pub fn tip_location_after(&self) -> &'static str {
        match self.lang {
            Language::English => "after",
            Language::Chinese => "后方",
        }
    }

    pub fn tip_amount(&self) -> &'static str {
        match self.lang {
            Language::English => "💰 Tip amount:",
            Language::Chinese => "💰 小费金额:",
        }
    }

    pub fn bundle_contains(&self) -> &'static str {
        match self.lang {
            Language::English => "📦 Bundle contains {} transactions:",
            Language::Chinese => "📦 捆绑包包含{}笔交易:",
        }
    }

    pub fn jito_tip_tx(&self) -> &'static str {
        match self.lang {
            Language::English => ". Jito tip transaction ⭐",
            Language::Chinese => ". Jito小费交易 ⭐",
        }
    }

    pub fn target_tx(&self) -> &'static str {
        match self.lang {
            Language::English => ". Target transaction 🎯",
            Language::Chinese => ". 目标交易 🎯",
        }
    }

    pub fn other_tx(&self) -> &'static str {
        match self.lang {
            Language::English => ". Other transaction",
            Language::Chinese => ". 其他交易",
        }
    }

    pub fn sandwich_detected(&self) -> &'static str {
        match self.lang {
            Language::English => "
🚨 Sandwich attack detected!",
            Language::Chinese => "
🚨 检测到三明治攻击!",
        }
    }

    pub fn front_tx(&self) -> &'static str {
        match self.lang {
            Language::English => "  Front-run transaction: https://solscan.io/tx/",
            Language::Chinese => "  前置交易: https://solscan.io/tx/",
        }
    }

    pub fn back_tx(&self) -> &'static str {
        match self.lang {
            Language::English => "  Back-run transaction: https://solscan.io/tx/",
            Language::Chinese => "  后置交易: https://solscan.io/tx/",
        }
    }

    pub fn shared_accounts(&self) -> &'static str {
        match self.lang {
            Language::English => "  Shared accounts:",
            Language::Chinese => "  共享账户数:",
        }
    }

    pub fn user_loss_estimation(&self) -> &'static str {
        match self.lang {
            Language::English => "
💸 Estimated User Loss:",
            Language::Chinese => "
💸 用户损失估算:",
        }
    }

    pub fn loss_amount(&self) -> &'static str {
        match self.lang {
            Language::English => "  Loss amount:",
            Language::Chinese => "  损失金额:",
        }
    }

    pub fn loss_percentage(&self) -> &'static str {
        match self.lang {
            Language::English => "  Loss percentage:",
            Language::Chinese => "  损失百分比:",
        }
    }

    pub fn mev_profit(&self) -> &'static str {
        match self.lang {
            Language::English => "  MEV profit:",
            Language::Chinese => "  MEV利润:",
        }
    }

    pub fn calculation_method(&self) -> &'static str {
        match self.lang {
            Language::English => "  Calculation method:",
            Language::Chinese => "  计算方法:",
        }
    }

    pub fn cannot_calculate_loss(&self) -> &'static str {
        match self.lang {
            Language::English => "  ⚠️ Unable to calculate specific loss amount",
            Language::Chinese => "  ⚠️ 无法计算具体损失金额",
        }
    }

    pub fn frontrun_skipped(&self) -> &'static str {
        match self.lang {
            Language::English => "  ℹ️ Front-run detection skipped (to avoid duplicate reporting)",
            Language::Chinese => "  ℹ️ 已跳过抢跑检测（避免重复报告）",
        }
    }

    pub fn frontrun_detected(&self) -> &'static str {
        match self.lang {
            Language::English => "
🚨 Front-run attack detected!",
            Language::Chinese => "
🚨 检测到抢跑攻击!",
        }
    }

    pub fn frontrun_tx(&self) -> &'static str {
        match self.lang {
            Language::English => "  Front-run transaction: https://solscan.io/tx/",
            Language::Chinese => "  抢跑交易: https://solscan.io/tx/",
        }
    }

    pub fn no_mev_detected(&self) -> &'static str {
        match self.lang {
            Language::English => "
✅ No MEV attack detected",
            Language::Chinese => "
✅ 未检测到MEV攻击",
        }
    }

    pub fn note(&self) -> &'static str {
        match self.lang {
            Language::English => "
⚠️ Note: Detection results are for reference only. Please verify with actual transaction data.",
            Language::Chinese => "
⚠️ 注意: 检测结果仅供参考，建议结合实际交易数据验证",
        }
    }

    pub fn no_jito_tip(&self) -> &'static str {
        match self.lang {
            Language::English => "✅ No Jito tip transaction found.",
            Language::Chinese => "✅ 未发现Jito小费交易",
        }
    }

    pub fn no_jito_tip_reasons(&self) -> [&'static str; 2] {
        match self.lang {
            Language::English => [
                "   • It might genuinely not be an MEV attack.",
                "   • The MEV attack was not conducted via a Jito bundle.",
            ],
            Language::Chinese => [
                "   • 确实没有被MEV攻击",
                "   • MEV攻击不是通过Jito捆绑包进行的",
            ],
        }
    }

    // --- MEV Messages ---

    pub fn jito_tip_found_before(&self) -> &'static str {
        match self.lang {
            Language::English => "Jito tip transaction found before target",
            Language::Chinese => "在目标交易前发现Jito小费交易",
        }
    }

    pub fn jito_tip_found_after(&self) -> &'static str {
        match self.lang {
            Language::English => "Jito tip transaction found after target",
            Language::Chinese => "在目标交易后发现Jito小费交易",
        }
    }

    pub fn jito_tip_parsed(&self) -> &'static str {
        match self.lang {
            Language::English => "Parsed Jito tip: {} lamports",
            Language::Chinese => "解析到Jito小费: {} lamports",
        }
    }

    pub fn sandwich_pattern_detected(&self) -> &'static str {
        match self.lang {
            Language::English => "Sandwich attack pattern detected, intersection similarity: ",
            Language::Chinese => "检测到三明治攻击模式，交集相似度: ",
        }
    }

    pub fn frontrun_pattern_detected(&self) -> &'static str {
        match self.lang {
            Language::English => "Front-run attack pattern detected, shared accounts: {}",
            Language::Chinese => "检测到抢跑攻击模式，共享账户数: {}",
        }
    }

    pub fn calculating_sandwich_loss(&self) -> &'static str {
        match self.lang {
            Language::English => "Calculating sandwich attack loss",
            Language::Chinese => "开始计算三明治攻击损失",
        }
    }

}