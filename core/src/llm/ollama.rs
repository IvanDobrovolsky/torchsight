use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

const BEAM_SYSTEM_PROMPT: &str = r#"You are TorchSight, a cybersecurity document classifier. Analyze the provided text and identify ALL security-relevant findings.

For each finding, output a JSON object with:
- category: one of [pii, credentials, financial, medical, confidential, malicious, safe]
- subcategory: specific type (e.g., pii.identity, malicious.injection, credentials.api_key)
- severity: one of [critical, high, medium, low, info]
- explanation: detailed explanation including specific values found (redact sensitive parts, e.g., SSN: 412-XX-7890, API key: sk_live_51HG...). Explain what was found, why it matters, and the risk.

If a document contains multiple types of sensitive data, return a finding for EACH one.
If the text is clean/safe, output a single finding with category "safe".

Respond ONLY with a JSON array of findings."#;

#[derive(Clone)]
pub struct OllamaClient {
    base_url: String,
    text_model: String,
    vision_model: String,
    client: reqwest::Client,
}

#[derive(Serialize)]
struct GenerateRequest {
    model: String,
    prompt: String,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    images: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct GenerateResponse {
    response: String,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct ChatOptions {
    num_predict: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    options: ChatOptions,
}

#[derive(Deserialize)]
struct ChatResponse {
    message: ChatResponseMessage,
}

#[derive(Deserialize)]
struct ChatResponseMessage {
    content: String,
}

impl OllamaClient {
    pub fn new(base_url: &str, text_model: &str, vision_model: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            text_model: text_model.to_string(),
            vision_model: vision_model.to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub fn text_model(&self) -> &str {
        &self.text_model
    }

    pub fn vision_model(&self) -> &str {
        &self.vision_model
    }

    pub async fn health_check(&self) -> Result<bool> {
        let resp = self
            .client
            .get(format!("{}/api/tags", self.base_url))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    /// Check if a model is available locally, and pull it if not
    pub async fn ensure_model(&self, model: &str) -> Result<bool> {
        // Check if model exists via /api/show
        let resp = self
            .client
            .post(format!("{}/api/show", self.base_url))
            .json(&serde_json::json!({ "name": model }))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => return Ok(true), // Already installed
            _ => {}
        }

        // Model not found — attempt to pull
        println!(
            "  {} Model '{}' not found locally. Pulling...",
            console::style("[AUTO-PULL]").yellow().bold(),
            model
        );

        let pull_resp = self
            .client
            .post(format!("{}/api/pull", self.base_url))
            .json(&serde_json::json!({ "name": model, "stream": false }))
            .timeout(std::time::Duration::from_secs(3600)) // 1 hour for large models
            .send()
            .await?;

        if pull_resp.status().is_success() {
            println!(
                "  {} Model '{}' pulled successfully.",
                console::style("[OK]").green().bold(),
                model
            );
            Ok(true)
        } else {
            let err = pull_resp.text().await.unwrap_or_default();
            println!(
                "  {} Failed to pull '{}': {}",
                console::style("[ERROR]").red().bold(),
                model,
                err
            );
            Ok(false)
        }
    }

    /// Text analysis — uses the fast text model
    pub async fn generate(&self, prompt: &str) -> Result<String> {
        self.generate_with_model(&self.text_model, prompt).await
    }

    /// General-purpose Q&A — uses the vision model (which can also do text reasoning)
    pub async fn generate_with_vision_model(&self, prompt: &str) -> Result<String> {
        self.generate_with_model(&self.vision_model, prompt).await
    }

    /// Beam text analysis — uses /api/generate with system prompt baked into prompt string
    /// (Beam's Modelfile template is `{{ .Prompt }}`, so /api/chat doesn't format correctly)
    pub async fn chat(&self, user_message: &str) -> Result<String> {
        let prompt = format!(
            "{}\n\n### Instruction:\n{}\n\n### Response:\n",
            BEAM_SYSTEM_PROMPT, user_message
        );

        let req = serde_json::json!({
            "model": self.text_model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0,
                "num_predict": 2048,
                "stop": ["\n\n\n"]
            }
        });

        let resp = self
            .client
            .post(format!("{}/api/generate", self.base_url))
            .json(&req)
            .timeout(std::time::Duration::from_secs(600))
            .send()
            .await?
            .error_for_status()?
            .json::<GenerateResponse>()
            .await?;

        Ok(resp.response)
    }

    /// Image description — uses the vision model (llama3.2-vision)
    pub async fn describe_image(&self, prompt: &str, image_bytes: &[u8]) -> Result<String> {
        let encoded = BASE64.encode(image_bytes);

        let req = GenerateRequest {
            model: self.vision_model.clone(),
            prompt: prompt.to_string(),
            stream: false,
            images: Some(vec![encoded]),
        };

        let resp = self
            .client
            .post(format!("{}/api/generate", self.base_url))
            .json(&req)
            .timeout(std::time::Duration::from_secs(600))
            .send()
            .await?
            .error_for_status()?
            .json::<GenerateResponse>()
            .await?;

        Ok(resp.response)
    }

    async fn generate_with_model(&self, model: &str, prompt: &str) -> Result<String> {
        let req = GenerateRequest {
            model: model.to_string(),
            prompt: prompt.to_string(),
            stream: false,
            images: None,
        };

        let resp = self
            .client
            .post(format!("{}/api/generate", self.base_url))
            .json(&req)
            .timeout(std::time::Duration::from_secs(600))
            .send()
            .await?
            .error_for_status()?
            .json::<GenerateResponse>()
            .await?;

        Ok(resp.response)
    }
}
