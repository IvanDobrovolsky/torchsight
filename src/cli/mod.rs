pub mod prompts;
pub mod repl;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub text_model: String,
    pub vision_model: String,
    pub ollama_url: String,
    pub max_size_bytes: u64,
    pub format: String,
}
