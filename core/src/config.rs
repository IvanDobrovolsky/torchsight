use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct TorchsightConfig {
    #[serde(default)]
    pub model: ModelConfig,
    #[serde(default)]
    pub scan: ScanSettings,
    #[serde(default)]
    pub report: ReportConfig,
}

#[derive(Debug, Deserialize)]
pub struct ModelConfig {
    #[serde(default = "default_text_model")]
    pub text: String,
    #[serde(default = "default_vision_model")]
    pub vision: String,
    #[serde(default = "default_ollama_url")]
    pub ollama_url: String,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            text: default_text_model(),
            vision: default_vision_model(),
            ollama_url: default_ollama_url(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ScanSettings {
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub fail_on: Option<String>,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            max_size_mb: default_max_size_mb(),
            exclude: Vec::new(),
            fail_on: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ReportConfig {
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub auto_pdf: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            auto_pdf: true,
        }
    }
}

fn default_text_model() -> String {
    "torchsight/beam".into()
}
fn default_vision_model() -> String {
    "llama3.2-vision".into()
}
fn default_ollama_url() -> String {
    "http://localhost:11434".into()
}
fn default_max_size_mb() -> u64 {
    1024
}
fn default_format() -> String {
    "json".into()
}

impl TorchsightConfig {
    /// Load config from .torchsight.toml in current directory or ancestors
    pub fn load() -> Self {
        // Check current directory and walk up to find config
        if let Ok(mut dir) = std::env::current_dir() {
            loop {
                let config_path = dir.join(".torchsight.toml");
                if config_path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&config_path) {
                        match toml::from_str::<TorchsightConfig>(&content) {
                            Ok(config) => {
                                tracing::debug!("Loaded config from {}", config_path.display());
                                return config;
                            }
                            Err(e) => {
                                eprintln!(
                                    "Warning: Failed to parse {}: {}",
                                    config_path.display(),
                                    e
                                );
                            }
                        }
                    }
                    break;
                }
                if !dir.pop() {
                    break;
                }
            }
        }

        Self::default()
    }
}
