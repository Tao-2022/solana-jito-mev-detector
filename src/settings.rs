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

    // 价格影响分析法参数
    #[serde(default)]
    pub price_impact: PriceImpactConfig,

    // Token余额变化分析法参数
    #[serde(default)]
    pub token_balance: TokenBalanceConfig,

    // 滑点估算法参数
    #[serde(default)]
    pub slippage: SlippageConfig,

    // SOL余额变化分析法参数
    #[serde(default)]
    pub sol_balance: SolBalanceConfig,

    // 交易规模估算参数
    #[serde(default)]
    pub trade_size: TradeSizeConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PriceImpactConfig {
    #[serde(default = "default_price_impact_ratio")]
    pub price_impact_ratio: f64,

    #[serde(default = "default_max_loss_percentage_price")]
    pub max_loss_percentage: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenBalanceConfig {
    #[serde(default = "default_token_loss_coefficient")]
    pub loss_coefficient: f64,

    #[serde(default = "default_max_loss_percentage_token")]
    pub max_loss_percentage: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SlippageConfig {
    #[serde(default = "default_base_slippage")]
    pub base_slippage: f64,

    #[serde(default = "default_complexity_factor")]
    pub complexity_factor: f64,

    #[serde(default = "default_instruction_factor")]
    pub instruction_factor: f64,

    #[serde(default = "default_max_loss_percentage_slippage")]
    pub max_loss_percentage: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SolBalanceConfig {
    #[serde(default = "default_impact_factor")]
    pub impact_factor: f64,

    #[serde(default = "default_conservative_ratio")]
    pub conservative_ratio: f64,

    #[serde(default = "default_max_loss_percentage_sol")]
    pub max_loss_percentage: f64,
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

fn default_price_impact_ratio() -> f64 {
    0.01
}
fn default_max_loss_percentage_price() -> f64 {
    10.0
}

fn default_token_loss_coefficient() -> f64 {
    0.005
}
fn default_max_loss_percentage_token() -> f64 {
    5.0
}

fn default_base_slippage() -> f64 {
    0.001
}
fn default_complexity_factor() -> f64 {
    0.2
}
fn default_instruction_factor() -> f64 {
    0.1
}
fn default_max_loss_percentage_slippage() -> f64 {
    3.0
}

fn default_impact_factor() -> f64 {
    0.6
}
fn default_conservative_ratio() -> f64 {
    0.3
}
fn default_max_loss_percentage_sol() -> f64 {
    8.0
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
            price_impact: PriceImpactConfig::default(),
            token_balance: TokenBalanceConfig::default(),
            slippage: SlippageConfig::default(),
            sol_balance: SolBalanceConfig::default(),
            trade_size: TradeSizeConfig::default(),
        }
    }
}

impl Default for PriceImpactConfig {
    fn default() -> Self {
        Self {
            price_impact_ratio: default_price_impact_ratio(),
            max_loss_percentage: default_max_loss_percentage_price(),
        }
    }
}

impl Default for TokenBalanceConfig {
    fn default() -> Self {
        Self {
            loss_coefficient: default_token_loss_coefficient(),
            max_loss_percentage: default_max_loss_percentage_token(),
        }
    }
}

impl Default for SlippageConfig {
    fn default() -> Self {
        Self {
            base_slippage: default_base_slippage(),
            complexity_factor: default_complexity_factor(),
            instruction_factor: default_instruction_factor(),
            max_loss_percentage: default_max_loss_percentage_slippage(),
        }
    }
}

impl Default for SolBalanceConfig {
    fn default() -> Self {
        Self {
            impact_factor: default_impact_factor(),
            conservative_ratio: default_conservative_ratio(),
            max_loss_percentage: default_max_loss_percentage_sol(),
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
