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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = TorchsightConfig::default();
        assert_eq!(config.model.text, "torchsight/beam");
        assert_eq!(config.model.vision, "llama3.2-vision");
        assert_eq!(config.model.ollama_url, "http://localhost:11434");
        assert_eq!(config.scan.max_size_mb, 1024);
        assert!(config.scan.exclude.is_empty());
        assert!(config.scan.fail_on.is_none());
        assert_eq!(config.report.format, "json");
        assert!(config.report.auto_pdf);
    }

    #[test]
    fn parse_partial_toml_uses_defaults() {
        let toml_str = r#"
[model]
text = "custom/model"
"#;
        let config: TorchsightConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.model.text, "custom/model");
        // Other model fields should use defaults
        assert_eq!(config.model.vision, "llama3.2-vision");
        assert_eq!(config.model.ollama_url, "http://localhost:11434");
        // Scan and report should use defaults
        assert_eq!(config.scan.max_size_mb, 1024);
        assert_eq!(config.report.format, "json");
    }

    #[test]
    fn parse_full_toml() {
        let toml_str = r#"
[model]
text = "my/beam"
vision = "my/vision"
ollama_url = "http://gpu-server:11434"

[scan]
max_size_mb = 512
exclude = ["*.log", "node_modules"]
fail_on = "high"

[report]
format = "html"
auto_pdf = false
"#;
        let config: TorchsightConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.model.text, "my/beam");
        assert_eq!(config.model.vision, "my/vision");
        assert_eq!(config.model.ollama_url, "http://gpu-server:11434");
        assert_eq!(config.scan.max_size_mb, 512);
        assert_eq!(config.scan.exclude, vec!["*.log", "node_modules"]);
        assert_eq!(config.scan.fail_on, Some("high".to_string()));
        assert_eq!(config.report.format, "html");
        assert!(!config.report.auto_pdf);
    }

    #[test]
    fn parse_empty_toml_uses_all_defaults() {
        let config: TorchsightConfig = toml::from_str("").unwrap();
        assert_eq!(config.model.text, "torchsight/beam");
        assert_eq!(config.scan.max_size_mb, 1024);
        assert_eq!(config.report.format, "json");
    }
}
