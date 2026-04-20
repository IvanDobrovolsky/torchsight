pub mod repl;
pub mod snake;
pub mod stdin;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub text_model: String,
    pub vision_model: String,
    pub ollama_url: String,
    pub max_size_bytes: u64,
    pub format: String,
    /// Suppress status messages (for clean structured output to stdout)
    #[serde(default)]
    pub quiet: bool,
}
