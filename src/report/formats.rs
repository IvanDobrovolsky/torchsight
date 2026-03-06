use anyhow::Result;
use chrono::Utc;
use console::style;
use genpdf::elements::{Break, Paragraph, TableLayout};
use genpdf::fonts;
use genpdf::style::Style;
use genpdf::{Alignment, Document, Element};

use super::builder::{ScanReport, Severity};

pub fn format_report(report: &ScanReport, format: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(report)?),
        "markdown" => Ok(format_markdown(report)),
        _ => Ok(format_terminal(report)),
    }
}

pub fn save_report(report: &ScanReport, format: &str) -> Result<String> {
    let timestamp = Utc::now().format("%Y-%m-%d_%H%M%S");

    match format {
        "pdf" => save_pdf(report, &timestamp.to_string()),
        _ => {
            let ext = match format {
                "json" => "json",
                "markdown" => "md",
                _ => "txt",
            };
            let filename = format!("torchsight_report_{}.{}", timestamp, ext);
            let content = format_report(report, format)?;
            std::fs::write(&filename, &content)?;
            Ok(filename)
        }
    }
}

fn titlecase(s: &str) -> String {
    s.replace('_', " ")
        .split_whitespace()
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn save_pdf(report: &ScanReport, timestamp: &str) -> Result<String> {
    let filename = format!("torchsight_report_{}.pdf", timestamp);

    let font_dirs = [
        "/usr/share/fonts/liberation",
        "/usr/share/fonts/TTF",
        "/usr/share/fonts/truetype/liberation",
        "/usr/share/fonts/truetype/liberation2",
    ];

    let font_family = font_dirs
        .iter()
        .find_map(|dir| fonts::from_files(dir, "LiberationSans", None).ok())
        .expect(
            "Could not find Liberation Sans font. Install ttf-liberation (or liberation-fonts).",
        );

    let mut doc = Document::new(font_family);
    doc.set_title("TorchSight Scan Report");
    doc.set_minimal_conformance();
    doc.set_paper_size(genpdf::PaperSize::A4);

    let margins = genpdf::SimplePageDecorator::new();
    doc.set_page_decorator(margins);

    let title_style = Style::new().bold().with_font_size(22);
    let subtitle_style = Style::new().with_font_size(11);
    let section_style = Style::new().bold().with_font_size(13);
    let file_heading_style = Style::new().bold().with_font_size(11);
    let bold_style = Style::new().bold().with_font_size(10);
    let normal_style = Style::new().with_font_size(10);
    let small_style = Style::new().with_font_size(8);
    let field_label_style = Style::new().bold().with_font_size(9);
    let field_value_style = Style::new().with_font_size(9);

    // ── Title Page Header ──
    doc.push(Break::new(1.5));
    doc.push(
        Paragraph::new("TORCHSIGHT")
            .aligned(Alignment::Center)
            .styled(title_style),
    );
    doc.push(
        Paragraph::new("Security Scan Report")
            .aligned(Alignment::Center)
            .styled(subtitle_style),
    );
    doc.push(Break::new(1.0));

    // ── Report metadata ──
    doc.push(
        Paragraph::new(format!(
            "Date:  {}",
            report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ))
        .styled(normal_style),
    );
    doc.push(
        Paragraph::new(format!("Files Scanned:  {}", report.files.len())).styled(normal_style),
    );
    doc.push(
        Paragraph::new(format!(
            "Files Flagged:  {}    Clean:  {}",
            report.flagged_count(),
            report.clean_count()
        ))
        .styled(normal_style),
    );
    doc.push(Break::new(0.3));
    doc.push(
        Paragraph::new("CONFIDENTIAL - All data processed on-premise. No information transmitted externally.")
            .styled(Style::new().bold().with_font_size(8)),
    );
    doc.push(Break::new(0.8));

    // ── Executive Summary Table ──
    doc.push(Paragraph::new("Executive Summary").styled(section_style));
    doc.push(Break::new(0.3));

    let mut summary_table = TableLayout::new(vec![2, 1]);
    summary_table
        .set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

    let summary_rows = [
        ("Total Findings", report.total_findings().to_string()),
        ("Critical", report.critical_count().to_string()),
        ("Warning", report.warning_count().to_string()),
        ("Informational", report.info_count().to_string()),
        (
            "Inappropriate Content",
            report.inappropriate_count().to_string(),
        ),
    ];
    for (label, value) in &summary_rows {
        let mut row = summary_table.row();
        row.push_element(Paragraph::new(*label).styled(normal_style));
        row.push_element(Paragraph::new(value.as_str()).styled(bold_style));
        row.push()?;
    }
    doc.push(summary_table);
    doc.push(Break::new(1.0));

    // ── Flagged Files (detailed) ──
    let flagged_files: Vec<_> = report
        .files
        .iter()
        .filter(|f| f.findings.iter().any(|finding| finding.category != "safe"))
        .collect();

    if !flagged_files.is_empty() {
        doc.push(Paragraph::new("Flagged Files - Detailed Findings").styled(section_style));
        doc.push(Break::new(0.3));

        for (idx, file) in flagged_files.iter().enumerate() {
            doc.push(
                Paragraph::new(format!(
                    "{}. {}",
                    idx + 1,
                    file.path
                ))
                .styled(file_heading_style),
            );
            doc.push(
                Paragraph::new(format!(
                    "Type: {}  |  Size: {}",
                    file.kind,
                    human_size(file.size)
                ))
                .styled(small_style),
            );
            doc.push(Break::new(0.2));

            for finding in &file.findings {
                if finding.category == "safe" {
                    continue;
                }

                let severity_label = if finding.category == "inappropriate" {
                    "FLAGGED".to_string()
                } else {
                    finding.severity.to_string()
                };

                doc.push(
                    Paragraph::new(format!(
                        "[{}]  {}",
                        severity_label, finding.description
                    ))
                    .styled(bold_style),
                );
                doc.push(
                    Paragraph::new(format!(
                        "Category: {}  |  Source: {}",
                        finding.category, finding.source
                    ))
                    .styled(small_style),
                );

                if !finding.evidence.is_empty() && finding.evidence != "[image content]" {
                    doc.push(
                        Paragraph::new(format!("Pattern: {}", finding.evidence))
                            .styled(small_style),
                    );
                }

                // Extracted data table
                if !finding.extracted_data.is_empty() {
                    doc.push(Break::new(0.1));

                    let mut table = TableLayout::new(vec![2, 5]);
                    table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(
                        true, true, false,
                    ));

                    let mut header = table.row();
                    header.push_element(Paragraph::new("Field").styled(field_label_style));
                    header.push_element(Paragraph::new("Extracted Value").styled(field_label_style));
                    header.push()?;

                    let mut keys: Vec<&String> = finding.extracted_data.keys().collect();
                    keys.sort();

                    for key in keys {
                        let value = &finding.extracted_data[key];
                        let mut row = table.row();
                        row.push_element(
                            Paragraph::new(titlecase(key)).styled(field_label_style),
                        );
                        row.push_element(Paragraph::new(value).styled(field_value_style));
                        row.push()?;
                    }

                    doc.push(table);
                }

                doc.push(Break::new(0.3));
            }

            doc.push(Break::new(0.4));
        }
    }

    // ── Clean Files List ──
    let clean_files: Vec<_> = report
        .files
        .iter()
        .filter(|f| !f.findings.iter().any(|finding| finding.category != "safe"))
        .collect();

    if !clean_files.is_empty() {
        doc.push(Break::new(0.5));
        doc.push(Paragraph::new("Clean Files").styled(section_style));
        doc.push(
            Paragraph::new("The following files were scanned and no security concerns were found.")
                .styled(small_style),
        );
        doc.push(Break::new(0.3));

        let mut clean_table = TableLayout::new(vec![5, 1, 2]);
        clean_table
            .set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

        let mut header = clean_table.row();
        header.push_element(Paragraph::new("File Path").styled(field_label_style));
        header.push_element(Paragraph::new("Type").styled(field_label_style));
        header.push_element(Paragraph::new("Size").styled(field_label_style));
        header.push()?;

        for file in &clean_files {
            let mut row = clean_table.row();
            row.push_element(Paragraph::new(&file.path).styled(field_value_style));
            row.push_element(
                Paragraph::new(format!("{}", file.kind)).styled(field_value_style),
            );
            row.push_element(
                Paragraph::new(human_size(file.size)).styled(field_value_style),
            );
            row.push()?;
        }

        doc.push(clean_table);
    }

    // ── Footer ──
    doc.push(Break::new(2.0));
    doc.push(
        Paragraph::new(
            "Generated by TorchSight | On-Premise Security Scanner | github.com/torchsight",
        )
        .aligned(Alignment::Center)
        .styled(small_style),
    );
    doc.push(
        Paragraph::new("All analysis performed locally. No data was transmitted to any external service.")
            .aligned(Alignment::Center)
            .styled(small_style),
    );

    doc.render_to_file(&filename)?;
    Ok(filename)
}

fn format_markdown(report: &ScanReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "# TorchSight Scan Report\n\n**Date:** {}\n\n",
        report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    out.push_str(&format!(
        "**Summary:** {} findings ({} critical, {} warning, {} info)\n\n",
        report.total_findings(),
        report.critical_count(),
        report.warning_count(),
        report.info_count(),
    ));

    out.push_str("---\n\n");

    for file in &report.files {
        out.push_str(&format!("## {}\n\n", file.path));
        out.push_str(&format!(
            "- **Type:** {}\n- **Size:** {} bytes\n- **Findings:** {}\n\n",
            file.kind,
            file.size,
            file.findings.len()
        ));

        for finding in &file.findings {
            let icon = match finding.severity {
                Severity::Critical => "[CRITICAL]",
                Severity::Warning => "[WARNING]",
                Severity::Info => "[INFO]",
            };
            out.push_str(&format!(
                "- {} {} - {} (source: {})\n",
                icon, finding.category, finding.description, finding.source
            ));
            if !finding.evidence.is_empty() {
                out.push_str(&format!("  - Evidence: `{}`\n", finding.evidence));
            }

            if !finding.extracted_data.is_empty() {
                out.push_str("  - **Extracted Data:**\n");
                let mut keys: Vec<&String> = finding.extracted_data.keys().collect();
                keys.sort();
                for key in keys {
                    let label = key.replace('_', " ");
                    out.push_str(&format!(
                        "    - {}: `{}`\n",
                        label, finding.extracted_data[key]
                    ));
                }
            }
        }

        out.push('\n');
    }

    out
}

fn format_terminal(report: &ScanReport) -> String {
    let mut out = String::new();

    for file in &report.files {
        let has_issues = file.findings.iter().any(|f| f.category != "safe");

        if has_issues {
            out.push_str(&format!(
                "\n  {} ({})\n",
                style(&file.path).bold(),
                file.kind
            ));
        } else {
            out.push_str(&format!(
                "\n  {} ({}) {}\n",
                style(&file.path).dim(),
                file.kind,
                style("[CLEAN]").green().bold()
            ));
        }

        for finding in &file.findings {
            if finding.category == "safe" {
                // Show safe files with their summary
                let summary = finding
                    .extracted_data
                    .get("summary")
                    .or_else(|| finding.extracted_data.get("subject"))
                    .map(|s| s.as_str())
                    .unwrap_or(&finding.description);
                out.push_str(&format!("    {}\n", style(summary).dim()));
                continue;
            }

            let severity_str = match (&finding.severity, finding.category.as_str()) {
                (_, "inappropriate") => {
                    format!("{}", style("FLAGGED").magenta().bold())
                }
                (Severity::Critical, _) => format!("{}", style("CRITICAL").red().bold()),
                (Severity::Warning, _) => format!("{}", style("WARNING").yellow().bold()),
                (Severity::Info, _) => format!("{}", style("INFO").dim()),
            };

            out.push_str(&format!(
                "    [{}] {} - {}\n",
                severity_str, finding.category, finding.description
            ));

            if !finding.evidence.is_empty() && finding.evidence != "[image content]" {
                out.push_str(&format!(
                    "           Evidence: {}\n",
                    style(&finding.evidence).dim()
                ));
            }

            if !finding.extracted_data.is_empty() {
                let mut keys: Vec<&String> = finding.extracted_data.keys().collect();
                keys.sort();
                for key in keys {
                    let label = key.replace('_', " ");
                    let value = &finding.extracted_data[key];
                    let colored_value = if finding.category == "inappropriate" {
                        format!("{}", style(value).magenta())
                    } else {
                        format!("{}", style(value).yellow())
                    };
                    out.push_str(&format!(
                        "           {}: {}\n",
                        style(label).dim(),
                        colored_value
                    ));
                }
            }
        }
    }

    out
}
