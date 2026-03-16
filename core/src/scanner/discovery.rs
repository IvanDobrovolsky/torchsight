use anyhow::Result;
use console::style;
use std::path::PathBuf;
use walkdir::WalkDir;

use super::classifier::FileKind;

/// Load ignore patterns from .torchsightignore file (gitignore-style)
fn load_ignore_patterns(root: &std::path::Path) -> Vec<String> {
    let mut patterns = Vec::new();

    // Check root directory
    let ignore_file = if root.is_file() {
        root.parent()
            .unwrap_or(std::path::Path::new("."))
            .join(".torchsightignore")
    } else {
        root.join(".torchsightignore")
    };

    if let Ok(content) = std::fs::read_to_string(&ignore_file) {
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                patterns.push(line.to_string());
            }
        }
    }

    // Also check cwd
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_ignore = cwd.join(".torchsightignore");
        if cwd_ignore.exists() && cwd_ignore != ignore_file {
            if let Ok(content) = std::fs::read_to_string(&cwd_ignore) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        patterns.push(line.to_string());
                    }
                }
            }
        }
    }

    patterns
}

/// Check if a path matches any ignore pattern (simple glob matching)
fn is_ignored(path: &std::path::Path, root: &std::path::Path, patterns: &[String]) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let rel_str = relative.to_string_lossy();

    for pattern in patterns {
        // Directory prefix match: "node_modules" matches any path containing it
        if !pattern.contains('*') && !pattern.contains('/') {
            for component in relative.components() {
                if component.as_os_str().to_string_lossy() == pattern.as_str() {
                    return true;
                }
            }
            // Also check filename
            if let Some(name) = path.file_name() {
                if name.to_string_lossy() == pattern.as_str() {
                    return true;
                }
            }
        }
        // Extension glob: "*.pyc"
        else if let Some(ext_pattern) = pattern.strip_prefix("*.") {
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy() == ext_pattern {
                    return true;
                }
            }
        }
        // Path glob with ** : "src/**/*.test.js"
        else if pattern.contains("**") {
            let parts: Vec<&str> = pattern.split("**").collect();
            if parts.len() == 2 {
                let prefix = parts[0].trim_end_matches('/');
                let suffix = parts[1].trim_start_matches('/');
                let rel = rel_str.as_ref();
                let prefix_ok = prefix.is_empty() || rel.starts_with(prefix);
                let suffix_ok = suffix.is_empty() || rel.ends_with(suffix);
                if prefix_ok && suffix_ok {
                    return true;
                }
            }
        }
        // Simple path prefix: "build/"
        else if pattern.ends_with('/') {
            let dir_name = pattern.trim_end_matches('/');
            for component in relative.components() {
                if component.as_os_str().to_string_lossy() == dir_name {
                    return true;
                }
            }
        }
    }

    false
}

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

    eprintln!(
        "  {} Scanning: {}",
        console::style("[PATH]").dim(),
        console::style(root.display()).cyan()
    );

    let ignore_patterns = load_ignore_patterns(&root);
    let scan_text = file_types.iter().any(|t| t == "text" || t == "all");
    let scan_images = file_types.iter().any(|t| t == "image" || t == "all");

    let mut files = Vec::new();
    let mut skipped_size = 0u64;
    let mut skipped_type = 0u64;
    let mut skipped_ignored = 0u64;

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

        // Check ignore patterns
        if !ignore_patterns.is_empty() && is_ignored(&file_path, &root, &ignore_patterns) {
            skipped_ignored += 1;
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
        eprintln!(
            "  {} Skipped {} files exceeding size limit",
            style("[INFO]").dim(),
            skipped_size
        );
    }
    if skipped_type > 0 {
        eprintln!(
            "  {} Skipped {} files (unsupported type)",
            style("[INFO]").dim(),
            skipped_type
        );
    }
    if skipped_ignored > 0 {
        eprintln!(
            "  {} Skipped {} files (.torchsightignore)",
            style("[INFO]").dim(),
            skipped_ignored
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // =========================================================================
    // classify_file
    // =========================================================================

    #[test]
    fn classify_text_extensions() {
        for ext in &["txt", "json", "py", "rs", "go", "java", "js", "html", "csv", "xml", "yaml", "sql", "sh", "pdf"] {
            let path = PathBuf::from(format!("test.{}", ext));
            assert_eq!(classify_file(&path), FileKind::Text, "Expected .{} to be Text", ext);
        }
    }

    #[test]
    fn classify_image_extensions() {
        for ext in &["png", "jpg", "jpeg", "gif", "bmp", "tiff", "tif", "webp"] {
            let path = PathBuf::from(format!("test.{}", ext));
            assert_eq!(classify_file(&path), FileKind::Image, "Expected .{} to be Image", ext);
        }
    }

    #[test]
    fn classify_unknown_extension() {
        let path = PathBuf::from("test.xyz123");
        assert_eq!(classify_file(&path), FileKind::Unknown);
    }

    #[test]
    fn classify_no_extension() {
        let path = PathBuf::from("Makefile");
        assert_eq!(classify_file(&path), FileKind::Unknown);
    }

    #[test]
    fn classify_case_insensitive() {
        let path = PathBuf::from("test.JSON");
        assert_eq!(classify_file(&path), FileKind::Text);

        let path = PathBuf::from("test.PNG");
        assert_eq!(classify_file(&path), FileKind::Image);
    }

    // =========================================================================
    // is_ignored
    // =========================================================================

    #[test]
    fn ignore_simple_directory_name() {
        let root = Path::new("/project");
        let path = Path::new("/project/node_modules/package/index.js");
        let patterns = vec!["node_modules".to_string()];
        assert!(is_ignored(path, root, &patterns));
    }

    #[test]
    fn ignore_simple_directory_name_no_match() {
        let root = Path::new("/project");
        let path = Path::new("/project/src/main.rs");
        let patterns = vec!["node_modules".to_string()];
        assert!(!is_ignored(path, root, &patterns));
    }

    #[test]
    fn ignore_extension_glob() {
        let root = Path::new("/project");
        let path = Path::new("/project/build/output.pyc");
        let patterns = vec!["*.pyc".to_string()];
        assert!(is_ignored(path, root, &patterns));
    }

    #[test]
    fn ignore_extension_glob_no_match() {
        let root = Path::new("/project");
        let path = Path::new("/project/src/main.py");
        let patterns = vec!["*.pyc".to_string()];
        assert!(!is_ignored(path, root, &patterns));
    }

    #[test]
    fn ignore_double_star_glob() {
        // The ** glob implementation checks prefix and suffix literally (no * expansion in suffix)
        let root = Path::new("/project");
        let path = Path::new("/project/src/tests/test_main.js");
        let patterns = vec!["src/**/test_main.js".to_string()];
        assert!(is_ignored(path, root, &patterns));
    }

    #[test]
    fn ignore_double_star_glob_with_empty_prefix() {
        let root = Path::new("/project");
        let path = Path::new("/project/deep/nested/file.txt");
        let patterns = vec!["**/file.txt".to_string()];
        assert!(is_ignored(path, root, &patterns));
    }

    #[test]
    fn ignore_directory_trailing_slash() {
        let root = Path::new("/project");
        let path = Path::new("/project/build/output.o");
        let patterns = vec!["build/".to_string()];
        assert!(is_ignored(path, root, &patterns));
    }

    #[test]
    fn ignore_filename_match() {
        let root = Path::new("/project");
        let path = Path::new("/project/.env");
        let patterns = vec![".env".to_string()];
        assert!(is_ignored(path, root, &patterns));
    }

    #[test]
    fn ignore_empty_patterns_matches_nothing() {
        let root = Path::new("/project");
        let path = Path::new("/project/src/main.rs");
        let patterns: Vec<String> = vec![];
        assert!(!is_ignored(path, root, &patterns));
    }

    // =========================================================================
    // discover_files with tempdir
    // =========================================================================

    #[test]
    fn discover_finds_text_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "Hello world").unwrap();
        std::fs::write(dir.path().join("data.json"), r#"{"key":"val"}"#).unwrap();

        let files = discover_files(
            dir.path().to_str().unwrap(),
            10 * 1024 * 1024,
            &["all".to_string()],
        ).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| f.kind == FileKind::Text));
    }

    #[test]
    fn discover_finds_image_files() {
        let dir = tempfile::tempdir().unwrap();
        // Create minimal PNG (8 bytes header + IHDR)
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        std::fs::write(dir.path().join("photo.png"), &png_header).unwrap();

        let files = discover_files(
            dir.path().to_str().unwrap(),
            10 * 1024 * 1024,
            &["all".to_string()],
        ).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].kind, FileKind::Image);
    }

    #[test]
    fn discover_respects_max_file_size() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("small.txt"), "small").unwrap();
        std::fs::write(dir.path().join("big.txt"), "x".repeat(2000)).unwrap();

        let files = discover_files(
            dir.path().to_str().unwrap(),
            1000, // 1000 bytes max
            &["all".to_string()],
        ).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].path.to_string_lossy().contains("small.txt"));
    }

    #[test]
    fn discover_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let files = discover_files(
            dir.path().to_str().unwrap(),
            10 * 1024 * 1024,
            &["all".to_string()],
        ).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn discover_skips_empty_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.txt"), "").unwrap();
        std::fs::write(dir.path().join("notempty.txt"), "content").unwrap();

        let files = discover_files(
            dir.path().to_str().unwrap(),
            10 * 1024 * 1024,
            &["all".to_string()],
        ).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn discover_nonexistent_path_errors() {
        let result = discover_files(
            "/nonexistent/path/that/does/not/exist",
            10 * 1024 * 1024,
            &["all".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn discover_respects_torchsightignore() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep.txt"), "keep me").unwrap();
        std::fs::write(dir.path().join("skip.log"), "skip me").unwrap();
        std::fs::write(dir.path().join(".torchsightignore"), "*.log\n").unwrap();

        let files = discover_files(
            dir.path().to_str().unwrap(),
            10 * 1024 * 1024,
            &["all".to_string()],
        ).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].path.to_string_lossy().contains("keep.txt"));
    }

    #[test]
    fn discover_filter_text_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("code.py"), "print('hi')").unwrap();
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        std::fs::write(dir.path().join("photo.png"), &png_header).unwrap();

        let files = discover_files(
            dir.path().to_str().unwrap(),
            10 * 1024 * 1024,
            &["text".to_string()],
        ).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].kind, FileKind::Text);
    }
}
