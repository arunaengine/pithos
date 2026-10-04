use crate::PithosCliError;
use pithos_lib::archive::CdcConfig;
use std::ops::Range;
use tracing_subscriber::{EnvFilter, filter::Directive};

pub fn evaluate_log_level(input: Option<String>) -> Result<EnvFilter, PithosCliError> {
    let level = if let Some(log_level) = input {
        &log_level.to_lowercase()
    } else {
        "info"
    };

    let invalid = || PithosCliError::InvalidArgumentError(format!("invalid log level: {level}"));
    let cli: Directive = format!("pithos={level}").parse().map_err(|_| invalid())?;
    let library: Directive = format!("pithos_lib={level}")
        .parse()
        .map_err(|_| invalid())?;
    Ok(EnvFilter::try_from_default_env()
        .unwrap_or("none".into())
        .add_directive(cli)
        .add_directive(library))
}

pub fn _to_hex_string(bytes: Vec<u8>) -> String {
    let hex_str: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    hex_str.join("")
}

pub fn parse_range_input(input: &str) -> Result<Range<u64>, PithosCliError> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 2 {
        return Err(PithosCliError::InvalidArgumentError(
            "ranges must use START:END".into(),
        ));
    }
    let start = parts[0].trim().parse::<u64>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse range start: {}", e))
    })?;
    let end = parts[1].trim().parse::<u64>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse range end: {}", e))
    })?;

    if start > end {
        return Err(PithosCliError::InvalidArgumentError(
            "range start must not exceed range end".into(),
        ));
    }
    Ok(start..end)
}

pub fn parse_cdc_input(input: &str) -> Result<CdcConfig, PithosCliError> {
    let parts: Vec<&str> = input.split(',').collect();
    if parts.len() != 3 {
        return Err(PithosCliError::InvalidArgumentError(
            "Invalid cdc argument".to_string(),
        ));
    }

    let min = parts[0].trim().parse::<usize>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse CDC minimum: {}", e))
    })?;
    let avg = parts[1].trim().parse::<usize>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse CDC average: {}", e))
    })?;
    let max = parts[2].trim().parse::<usize>().map_err(|e| {
        PithosCliError::InvalidArgumentError(format!("Failed to parse CDC maximum: {}", e))
    })?;

    CdcConfig::new(min, avg, max).map_err(PithosCliError::PithosError)
}
