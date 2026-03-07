use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

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
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
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

    /// Text analysis — uses the fast text model
    pub async fn generate(&self, prompt: &str) -> Result<String> {
        self.generate_with_model(&self.text_model, prompt).await
    }

    /// Chat-based text analysis (for models trained with chat format)
    pub async fn chat(&self, user_message: &str) -> Result<String> {
        let req = ChatRequest {
            model: self.text_model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: user_message.to_string(),
            }],
            stream: false,
        };

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&req)
            .timeout(std::time::Duration::from_secs(300))
            .send()
            .await?
            .error_for_status()?
            .json::<ChatResponse>()
            .await?;

        Ok(resp.message.content)
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
            .timeout(std::time::Duration::from_secs(180))
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
            .timeout(std::time::Duration::from_secs(300))
            .send()
            .await?
            .error_for_status()?
            .json::<GenerateResponse>()
            .await?;

        Ok(resp.response)
    }
}
