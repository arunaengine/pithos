use peak_alloc::PeakAlloc;
use std::io::Write;
use std::time::Instant;

#[global_allocator]
pub static PEAK_ALLOC: PeakAlloc = PeakAlloc;

pub struct Metrics {
    pub archive_bytes: u64,
    pub output_bytes: u64,
    pub source_read_count: Option<u64>,
    pub source_read_bytes: Option<u64>,
    pub bytes_appended: Option<u64>,
    pub dedup_signal: Option<bool>,
}

impl Metrics {
    #[allow(dead_code)] // The archive-path binary is the only target with operation-only metrics.
    pub fn archive(archive_bytes: u64) -> Self {
        Self {
            archive_bytes,
            output_bytes: archive_bytes,
            source_read_count: None,
            source_read_bytes: None,
            bytes_appended: None,
            dedup_signal: None,
        }
    }

    #[allow(dead_code)] // Only the archive-path binary measures operations without archive output.
    pub fn operation() -> Self {
        Self {
            archive_bytes: 0,
            output_bytes: 0,
            source_read_count: None,
            source_read_bytes: None,
            bytes_appended: None,
            dedup_signal: None,
        }
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)] // Only the archive I/O, adapter, and block-pipeline binaries write to a sink.
pub struct CountingSink(pub u64);

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[allow(dead_code)] // Only the adapter, append, and block-pipeline binaries generate payloads.
pub fn deterministic_bytes(seed: u64, length: usize) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| next_deterministic_byte(&mut state))
        .collect()
}

#[allow(dead_code)] // The virtual reader generates deterministic bytes without allocating its input.
pub fn next_deterministic_byte(state: &mut u64) -> u8 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    (*state >> 56) as u8
}

fn json_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn json_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

/// Records one local resource sample. Criterion's estimates remain the runtime distribution.
pub fn measure<T>(
    workload: &str,
    setup: &str,
    operation: impl FnOnce() -> T,
    metrics: impl FnOnce(&T) -> Metrics,
) {
    let baseline = PEAK_ALLOC.current_usage();
    PEAK_ALLOC.reset_peak_usage();
    let started = Instant::now();
    let result = operation();
    let elapsed_local_ns = started.elapsed().as_nanos();
    let peak_heap_bytes = PEAK_ALLOC.peak_usage().saturating_sub(baseline);
    let metrics = metrics(&result);
    println!(
        "{{\"schema\":\"pithos-bench-v1\",\"workload\":\"{workload}\",\"setup\":\"{setup}\",\"elapsed_local_ns\":{elapsed_local_ns},\"peak_heap_bytes\":{peak_heap_bytes},\"archive_bytes\":{},\"output_bytes\":{},\"source_read_count\":{},\"source_read_bytes\":{},\"bytes_appended\":{},\"dedup_signal\":{}}}",
        metrics.archive_bytes,
        metrics.output_bytes,
        json_u64(metrics.source_read_count),
        json_u64(metrics.source_read_bytes),
        json_u64(metrics.bytes_appended),
        json_bool(metrics.dedup_signal),
    );
}
