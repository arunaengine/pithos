// Compiler messages change between releases, so the expected output pins the MSRV compiler.
#[rustversion::attr(not(stable(1.89)), ignore = "expected output is from Rust 1.89")]
#[test]
fn secret_ownership_and_writer_typestate_are_compile_time_enforced() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/non_copy_static_secret.rs");
    cases.compile_fail("tests/ui/writer_finish_consumes_writer.rs");
    cases.compile_fail("tests/ui/writer_use_after_finish.rs");
    cases.compile_fail("tests/ui/incomplete_writer_cannot_resume.rs");
    cases.compile_fail("tests/ui/crypt4gh_header_is_private.rs");
}
