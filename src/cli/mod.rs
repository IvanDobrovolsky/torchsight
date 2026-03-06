pub mod prompts;
pub mod repl;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub model: String,
    pub ollama_url: String,
    pub max_size_bytes: u64,
    pub format: String,
    pub fast_only: bool,
}
