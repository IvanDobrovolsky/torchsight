use anyhow::Result;
use std::path::Path;
use std::process::Command;

pub struct OcrResult {
    pub text: String,
    pub confidence: f32,
}

pub fn extract_text(image_path: &Path) -> Result<OcrResult> {
    // Run tesseract with TSV output to get confidence scores
    let tsv_output = Command::new("tesseract")
        .arg(image_path.as_os_str())
        .arg("stdout")
        .arg("--psm")
        .arg("3") // Fully automatic page segmentation
        .arg("-l")
        .arg("eng")
        .arg("tsv")
        .output()?;

    if !tsv_output.status.success() {
        let stderr = String::from_utf8_lossy(&tsv_output.stderr);
        anyhow::bail!("Tesseract failed: {}", stderr);
    }

    let tsv = String::from_utf8_lossy(&tsv_output.stdout);

    // Parse TSV to extract text and average confidence
    let mut text_parts: Vec<String> = Vec::new();
    let mut confidences: Vec<f32> = Vec::new();
    let mut last_block = -1i32;
    let mut last_line = -1i32;

    for line in tsv.lines().skip(1) {
        // TSV columns: level, page, block, par, line, word, left, top, width, height, conf, text
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 12 {
            continue;
        }

        let conf: f32 = cols[10].parse().unwrap_or(-1.0);
        let text = cols[11].trim();

        if text.is_empty() || conf < 0.0 {
            continue;
        }

        let block: i32 = cols[2].parse().unwrap_or(0);
        let line_num: i32 = cols[4].parse().unwrap_or(0);

        // Add newlines between blocks/lines
        if block != last_block && last_block >= 0 {
            text_parts.push("\n\n".to_string());
        } else if line_num != last_line && last_line >= 0 {
            text_parts.push("\n".to_string());
        }

        text_parts.push(text.to_string());
        text_parts.push(" ".to_string());
        confidences.push(conf);

        last_block = block;
        last_line = line_num;
    }

    let full_text = text_parts.concat().trim().to_string();
    let avg_confidence = if confidences.is_empty() {
        0.0
    } else {
        confidences.iter().sum::<f32>() / confidences.len() as f32
    };

    Ok(OcrResult {
        text: full_text,
        confidence: avg_confidence,
    })
}

pub fn is_available() -> bool {
    Command::new("tesseract")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
