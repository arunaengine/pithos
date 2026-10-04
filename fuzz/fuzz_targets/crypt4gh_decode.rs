#![no_main]

use libfuzzer_sys::fuzz_target;
use pithos_lib::fuzzing::decode_crypt4gh_header;

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(decode_crypt4gh_header(data));
});
