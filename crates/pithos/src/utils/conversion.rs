use crate::PithosCliError;
use std::ops::Range;
use tracing::Level;

pub fn evaluate_log_level(input: Option<String>) -> Level {
    if let Some(log_level) = input {
        match log_level.to_lowercase().as_str() {
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            "debug" => Level::DEBUG,
            "trace" => Level::TRACE,
            _ => Level::INFO,
        }
    } else {
        Level::INFO
    }
}

pub fn _to_hex_string(bytes: Vec<u8>) -> String {
    let hex_str: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    hex_str.join("")
}

pub fn parse_range_input(input: &str) -> Result<Vec<Range<u64>>, PithosCliError> {
    if input.is_empty() {
        return Err(PithosCliError::InvalidArgumentError(
            "Provided empty ranges argument".to_string(),
        ));
    }

    let ranges: Vec<&str> = input.split(',').collect();
    let mut parsed_ranges = Vec::new();
    for range in ranges {
        let parts: Vec<&str> = range.split(':').collect();

        let start = parts[0].trim().parse::<u64>().map_err(|e| {
            PithosCliError::InvalidArgumentError(format!("Failed to parse range start: {}", e))
        })?;
        let end = parts[1].trim().parse::<u64>().map_err(|e| {
            PithosCliError::InvalidArgumentError(format!("Failed to parse range end: {}", e))
        })?;

        parsed_ranges.push(start..end)
    }

    Ok(parsed_ranges)
}
