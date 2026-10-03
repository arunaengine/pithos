use peak_alloc::PeakAlloc;
use pithos_lib::archive::{
    ArchivePath, ArchiveWriter, CdcConfig, Chunking, EntryMetadata, ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use std::io::{Read, Write};

#[global_allocator]
static PEAK_ALLOC: PeakAlloc = PeakAlloc;

struct VirtualReader {
    remaining: u64,
    state: u64,
}

impl VirtualReader {
    fn new(length: u64) -> Self {
        Self {
            remaining: length,
            state: 0x9e37_79b9_7f4a_7c15,
        }
    }
}

impl Read for VirtualReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.remaining.min(buffer.len() as u64) as usize;
        for byte in &mut buffer[..count] {
            self.state = self
                .state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *byte = (self.state >> 56) as u8;
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}

#[derive(Debug, Default)]
struct CountingSink(u64);

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn streamed_peak(logical_bytes: u64) -> (u64, u64) {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let baseline = PEAK_ALLOC.current_usage();
    PEAK_ALLOC.reset_peak_usage();
    let mut writer = ArchiveWriter::create(
        CountingSink::default(),
        WriteOptions::new(sender, vec![recipient])
            .with_chunking(Chunking::ContentDefined(CdcConfig::DEFAULT)),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("streamed.bin").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 3).unwrap(),
            Some(logical_bytes),
            VirtualReader::new(logical_bytes),
        )
        .unwrap();
    let sink = writer.finish().unwrap();
    (
        PEAK_ALLOC.peak_usage().saturating_sub(baseline) as u64,
        sink.0,
    )
}

#[test]
fn streamed_writer_memory_is_bounded_by_block_working_set() {
    let small_logical_bytes = CdcConfig::DEFAULT.max_size() as u64;
    let large_logical_bytes = 32 * 1024 * 1024;
    let (small_peak, small_output) = streamed_peak(small_logical_bytes);
    let (large_peak, large_output) = streamed_peak(large_logical_bytes);
    let permitted_delta = 8 * 1024 * 1024u64;
    let peak_delta = large_peak.saturating_sub(small_peak);

    println!(
        "{{\"schema\":\"pithos-memory-v1\",\"workload\":\"streamed_writer_memory\",\"small_logical_bytes\":{small_logical_bytes},\"large_logical_bytes\":{large_logical_bytes},\"cdc_min_bytes\":{},\"cdc_avg_bytes\":{},\"cdc_max_bytes\":{},\"small_peak_heap_bytes\":{small_peak},\"large_peak_heap_bytes\":{large_peak},\"peak_delta_bytes\":{peak_delta},\"permitted_delta_bytes\":{permitted_delta},\"small_output_bytes\":{small_output},\"large_output_bytes\":{large_output}}}",
        CdcConfig::DEFAULT.min_size(),
        CdcConfig::DEFAULT.avg_size(),
        CdcConfig::DEFAULT.max_size(),
    );

    assert!(small_output > 0);
    assert!(large_output > small_output);
    // Both inputs exceed the configured maximum CDC block. Eight MiB allows the second block's
    // directory/reference bookkeeping while rejecting retention of the 16 MiB logical delta.
    assert!(
        large_peak <= small_peak.saturating_add(permitted_delta),
        "large stream peak {large_peak} exceeded small stream peak {small_peak} by more than 8 MiB"
    );
}
