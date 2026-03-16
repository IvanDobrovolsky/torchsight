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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filekind_display() {
        assert_eq!(format!("{}", FileKind::Text), "text");
        assert_eq!(format!("{}", FileKind::Image), "image");
        assert_eq!(format!("{}", FileKind::Unknown), "unknown");
    }

    #[test]
    fn filekind_equality() {
        assert_eq!(FileKind::Text, FileKind::Text);
        assert_eq!(FileKind::Image, FileKind::Image);
        assert_eq!(FileKind::Unknown, FileKind::Unknown);
        assert_ne!(FileKind::Text, FileKind::Image);
        assert_ne!(FileKind::Text, FileKind::Unknown);
    }

    #[test]
    fn filekind_clone() {
        let kind = FileKind::Text;
        let cloned = kind.clone();
        assert_eq!(kind, cloned);
    }

    #[test]
    fn filekind_serialize_deserialize() {
        let kind = FileKind::Text;
        let json = serde_json::to_string(&kind).unwrap();
        let deserialized: FileKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, deserialized);
    }
}
