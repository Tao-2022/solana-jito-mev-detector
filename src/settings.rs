use crate::locale::Language;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub rpc_url: String,
    pub log_level: String,
    #[serde(default)]
    pub language: Language,
    #[serde(default)]
    pub auto_detect_hashes: Vec<String>,
    #[serde(default)]
    pub mev_detection: MevDetectionConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MevDetectionConfig {
    // 交易相似度计算参数
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f64,

    // 小额转账阈值 (lamports)
    #[serde(default = "default_small_transfer_threshold")]
    pub small_transfer_threshold: u64,

    // 交易规模估算参数
    #[serde(default)]
    pub trade_size: TradeSizeConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TradeSizeConfig {
    #[serde(default = "default_min_swap_accounts")]
    pub min_swap_accounts: usize,

    #[serde(default = "default_instruction_complexity_value")]
    pub instruction_complexity_value: u64,

    #[serde(default = "default_account_factor_value")]
    pub account_factor_value: u64,

    #[serde(default = "default_min_trade_size")]
    pub min_trade_size: u64,
}

// 默认值函数
fn default_similarity_threshold() -> f64 {
    0.5
}
fn default_small_transfer_threshold() -> u64 {
    1_000_000
}

fn default_min_swap_accounts() -> usize {
    6
}
fn default_instruction_complexity_value() -> u64 {
    100_000_000
}
fn default_account_factor_value() -> u64 {
    50_000_000
}
fn default_min_trade_size() -> u64 {
    100_000_000
}

impl Default for MevDetectionConfig {
    fn default() -> Self {
        Self {
            similarity_threshold: default_similarity_threshold(),
            small_transfer_threshold: default_small_transfer_threshold(),
            trade_size: TradeSizeConfig::default(),
        }
    }
}
impl Default for TradeSizeConfig {
    fn default() -> Self {
        Self {
            min_swap_accounts: default_min_swap_accounts(),
            instruction_complexity_value: default_instruction_complexity_value(),
            account_factor_value: default_account_factor_value(),
            min_trade_size: default_min_trade_size(),
        }
    }
}
