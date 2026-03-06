mod builder;
mod formats;

pub use builder::{FileFinding, ScanReport, Severity};
pub use formats::{format_report, save_report};
