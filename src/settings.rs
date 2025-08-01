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

    // 忽略Jito功能 - 开启后不查询Jito API，不检查Jito小费，直接基于账户重合分析MEV
    #[serde(default = "default_ignore_jito")]
    pub ignore_jito: bool,
}

// 默认值函数
fn default_similarity_threshold() -> f64 {
    0.5
}

fn default_small_transfer_threshold() -> u64 {
    1_000_000
}

fn default_ignore_jito() -> bool {
    false
}

impl Default for MevDetectionConfig {
    fn default() -> Self {
        Self {
            similarity_threshold: default_similarity_threshold(),
            small_transfer_threshold: default_small_transfer_threshold(),
            ignore_jito: default_ignore_jito(),
        }
    }
}
