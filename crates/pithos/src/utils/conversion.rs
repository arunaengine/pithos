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

pub fn parse_range_input(input: &str) -> Result<Range<u64>, PithosCliError> {
    let parts: Vec<&str> = input.split(':').collect();
    let start = parts[0].trim().parse::<u64>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse range start: {}", e))
    })?;
    let end = parts[1].trim().parse::<u64>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse range end: {}", e))
    })?;

    Ok(start..end)
}

pub fn parse_cdc_input(input: &str) -> Result<(u32, u32, u32), PithosCliError> {
    let parts: Vec<&str> = input.split(',').collect();
    if parts.len() != 3 {
        return Err(PithosCliError::InvalidArgumentError(
            "Invalid cdc argument".to_string(),
        ));
    }

    let min = parts[0].trim().parse::<u32>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse range start: {}", e))
    })?;
    let avg = parts[1].trim().parse::<u32>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse range end: {}", e))
    })?;
    let max = parts[2].trim().parse::<u32>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse range end: {}", e))
    })?;

    Ok((min, avg, max))
}
