use anyhow::Result;
use console::style;
use std::path::PathBuf;
use walkdir::WalkDir;

use super::classifier::FileKind;

pub struct ScannableFile {
    pub path: PathBuf,
    pub size: u64,
    pub kind: FileKind,
}

const TEXT_EXTENSIONS: &[&str] = &[
    "txt", "csv", "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "log", "md",
    "rst", "html", "htm", "css", "js", "ts", "py", "rs", "go", "java", "c", "cpp", "h", "hpp",
    "rb", "php", "sh", "bash", "zsh", "sql", "env", "pem", "key", "crt", "pub", "tex", "rtf",
    "pdf",
];

const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "bmp", "tiff", "tif", "webp"];

pub fn discover_files(
    path: &str,
    max_size_bytes: u64,
    file_types: &[String],
) -> Result<Vec<ScannableFile>> {
    let cwd = std::env::current_dir()?;

    // Treat "/" and "." as the current working directory
    let root = match path.trim() {
        "/" | "." | "./" | "" => cwd.clone(),
        other => {
            let p = PathBuf::from(other);
            if p.is_absolute() {
                p
            } else {
                cwd.join(p)
            }
        }
    };

    let root = root.canonicalize().unwrap_or(root);

    if !root.exists() {
        anyhow::bail!("Path does not exist: {}", root.display());
    }

    println!(
        "  {} Scanning: {}",
        console::style("[PATH]").dim(),
        console::style(root.display()).cyan()
    );

    let scan_text = file_types.iter().any(|t| t == "text" || t == "all");
    let scan_images = file_types.iter().any(|t| t == "image" || t == "all");

    let mut files = Vec::new();
    let mut skipped_size = 0u64;
    let mut skipped_type = 0u64;

    let walker = if root.is_file() {
        WalkDir::new(&root).max_depth(0)
    } else {
        WalkDir::new(&root)
    };

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let file_path = entry.path().to_path_buf();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        let size = metadata.len();

        if size > max_size_bytes {
            skipped_size += 1;
            continue;
        }

        if size == 0 {
            continue;
        }

        let kind = classify_file(&file_path);

        match kind {
            FileKind::Text if !scan_text => {
                skipped_type += 1;
                continue;
            }
            FileKind::Image if !scan_images => {
                skipped_type += 1;
                continue;
            }
            FileKind::Unknown => {
                skipped_type += 1;
                continue;
            }
            _ => {}
        }

        files.push(ScannableFile {
            path: file_path,
            size,
            kind,
        });
    }

    if skipped_size > 0 {
        println!(
            "  {} Skipped {} files exceeding size limit",
            style("[INFO]").dim(),
            skipped_size
        );
    }
    if skipped_type > 0 {
        println!(
            "  {} Skipped {} files (unsupported type)",
            style("[INFO]").dim(),
            skipped_type
        );
    }

    Ok(files)
}

fn classify_file(path: &PathBuf) -> FileKind {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if TEXT_EXTENSIONS.contains(&ext.as_str()) {
        return FileKind::Text;
    }

    if IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return FileKind::Image;
    }

    // Try magic bytes for images
    if let Ok(kind) = infer::get_from_path(path) {
        if let Some(k) = kind {
            if k.mime_type().starts_with("image/") {
                return FileKind::Image;
            }
            if k.mime_type().starts_with("text/") {
                return FileKind::Text;
            }
        }
    }

    FileKind::Unknown
}
