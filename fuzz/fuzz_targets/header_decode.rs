#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _category = pithos_lib::fuzzing::decode_header(data);
    std::hint::black_box(_category);
});
