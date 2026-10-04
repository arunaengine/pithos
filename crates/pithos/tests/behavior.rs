use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMPORARY: AtomicUsize = AtomicUsize::new(0);

fn workspace_file(path: &str) -> String {
    format!(
        "{}/../pithos_lib/tests/data/{path}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn temporary() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pithos-cli-behavior-{}-{}",
        std::process::id(),
        NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pithos"))
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_clean_failure(output: &Output) -> String {
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr).into_owned();
    for forbidden in ["panicked", "unwrap", "expect", "unimplemented"] {
        assert!(!message.contains(forbidden), "{message}");
    }
    message
}

fn create_archive(root: &Path, recipients: &[&str]) -> PathBuf {
    let first = root.join("first.txt");
    let second = root.join("second.txt");
    let archive = root.join("archive.pith");
    fs::write(&first, b"first content").unwrap();
    fs::write(&second, b"second content").unwrap();

    let mut invocation = command();
    invocation
        .arg("--secret-key")
        .arg(workspace_file("keys/sender_private.pem"));
    for recipient in recipients {
        invocation
            .arg("--public-keys")
            .arg(workspace_file(recipient));
    }
    let output = invocation
        .arg("--output")
        .arg(&archive)
        .arg("create")
        .arg("--cdc")
        .arg("64,256,1024")
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert_success(&output);
    archive
}

#[test]
fn create_read_extract_export_and_keypair_success_matrix() {
    let temporary = temporary();
    let archive = create_archive(
        &temporary,
        &["keys/recipient1_public.pem", "keys/recipient2_public.pem"],
    );
    let reader_key = workspace_file("keys/recipient1_private.pem");

    for (subcommand, expected) in [
        (["read", "list"].as_slice(), "first.txt"),
        (["read", "directory"].as_slice(), "second.txt"),
    ] {
        let output = command()
            .arg("--secret-key")
            .arg(&reader_key)
            .args(subcommand)
            .arg(&archive)
            .output()
            .unwrap();
        assert_success(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains(expected));
    }

    let info = command()
        .arg("--secret-key")
        .arg(&reader_key)
        .arg("read")
        .arg("info")
        .arg(&archive)
        .arg("first.txt")
        .output()
        .unwrap();
    assert_success(&info);
    assert!(String::from_utf8_lossy(&info.stdout).contains("first.txt"));

    let range_output = temporary.join("range.bin");
    let range = command()
        .arg("--secret-key")
        .arg(&reader_key)
        .arg("--output")
        .arg(&range_output)
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("first.txt")
        .arg("--ranges")
        .arg("0:5")
        .output()
        .unwrap();
    assert_success(&range);
    assert_eq!(fs::read(&range_output).unwrap(), b"first");

    let extraction = temporary.join("extract");
    fs::create_dir(&extraction).unwrap();
    let all = command()
        .arg("--secret-key")
        .arg(&reader_key)
        .arg("--output")
        .arg(&extraction)
        .arg("read")
        .arg("all")
        .arg(&archive)
        .output()
        .unwrap();
    assert_success(&all);
    assert_eq!(
        fs::read(extraction.join("first.txt")).unwrap(),
        b"first content"
    );
    assert_eq!(
        fs::read(extraction.join("second.txt")).unwrap(),
        b"second content"
    );

    let exported = temporary.join("first.c4gh");
    let export = command()
        .arg("--secret-key")
        .arg(&reader_key)
        .arg("--public-keys")
        .arg(workspace_file("keys/recipient2_public.pem"))
        .arg("--output")
        .arg(&exported)
        .arg("export")
        .arg("--format")
        .arg("crypt4gh")
        .arg(&archive)
        .arg("first.txt")
        .output()
        .unwrap();
    assert_success(&export);
    assert!(fs::read(&exported).unwrap().starts_with(b"crypt4gh"));

    let keypair = command().arg("keypair").output().unwrap();
    assert_success(&keypair);
    let pem = String::from_utf8(keypair.stdout).unwrap();
    assert!(pem.contains("BEGIN PRIVATE KEY"));
    assert!(pem.contains("BEGIN PUBLIC KEY"));

    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn read_data_requires_at_least_one_archive_path() {
    let temporary = temporary();
    let archive = create_archive(&temporary, &["keys/recipient1_public.pem"]);
    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("read")
        .arg("data")
        .arg(&archive)
        .output()
        .unwrap();

    let message = assert_clean_failure(&output);
    assert!(message.contains("at least one archive path"), "{message}");
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn unavailable_content_and_corrupt_archives_have_distinct_failures() {
    let temporary = temporary();
    let archive = create_archive(&temporary, &["keys/recipient1_public.pem"]);

    let unavailable = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient2_private.pem"))
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("first.txt")
        .output()
        .unwrap();
    let unavailable_message = assert_clean_failure(&unavailable);
    assert!(
        unavailable_message.contains("unavailable"),
        "{unavailable_message}"
    );

    let corrupt = temporary.join("corrupt.pith");
    let mut bytes = fs::read(&archive).unwrap();
    bytes[0] ^= 1;
    fs::write(&corrupt, bytes).unwrap();
    let invalid = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("read")
        .arg("list")
        .arg(&corrupt)
        .output()
        .unwrap();
    let corrupt_message = assert_clean_failure(&invalid);
    assert!(
        !corrupt_message.contains("unavailable"),
        "{corrupt_message}"
    );
    assert_ne!(unavailable_message, corrupt_message);
    let _ = fs::remove_dir_all(temporary);
}
