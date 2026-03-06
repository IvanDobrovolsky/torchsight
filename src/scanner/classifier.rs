use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FileKind {
    Text,
    Image,
    Unknown,
}

impl std::fmt::Display for FileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileKind::Text => write!(f, "text"),
            FileKind::Image => write!(f, "image"),
            FileKind::Unknown => write!(f, "unknown"),
        }
    }
}
