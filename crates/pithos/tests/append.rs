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
        "pithos-cli-append-{}-{}",
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

fn sender_command() -> Command {
    let mut command = command();
    command
        .arg("--secret-key")
        .arg(workspace_file("keys/sender_private.pem"));
    command
}

fn add_recipient(command: &mut Command, name: &str) {
    command
        .arg("--public-keys")
        .arg(workspace_file(&format!("keys/{name}_public.pem")));
}

fn create_archive(directory: &Path) -> PathBuf {
    let input = directory.join("base.txt");
    let archive = directory.join("archive.pith");
    fs::write(&input, b"base cli append payload").unwrap();
    let mut create = sender_command();
    add_recipient(&mut create, "sender");
    add_recipient(&mut create, "recipient1");
    assert!(
        create
            .arg("--output")
            .arg(&archive)
            .arg("create")
            .arg(&input)
            .status()
            .unwrap()
            .success()
    );
    archive
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn append_files_accepts_cdc_and_sync_all_and_publishes_readable_content() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let input = temporary.join("appended.txt");
    fs::write(&input, b"appended by cli").unwrap();
    let mut append = sender_command();
    add_recipient(&mut append, "sender");
    add_recipient(&mut append, "recipient1");

    let output = append
        .arg("append")
        .arg("files")
        .arg("--file")
        .arg(&archive)
        .arg("--cdc")
        .arg("64,256,1024")
        .arg("--durability")
        .arg("sync-all")
        .arg(&input)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let read = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("appended.txt")
        .output()
        .unwrap();
    assert!(read.status.success(), "{}", stderr(&read));
    assert_eq!(read.stdout, b"appended by cli");
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn append_readers_grants_selected_content_under_the_appender_lock() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let mut grant = sender_command();
    add_recipient(&mut grant, "recipient2");

    let output = grant
        .arg("append")
        .arg("readers")
        .arg("--ids")
        .arg("0")
        .arg("--durability")
        .arg("sync-all")
        .arg(&archive)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let read = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient2_private.pem"))
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("base.txt")
        .output()
        .unwrap();
    assert!(read.status.success(), "{}", stderr(&read));
    assert_eq!(read.stdout, b"base cli append payload");
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn append_preflight_and_self_ingestion_fail_without_mutating_the_archive() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let original = fs::read(&archive).unwrap();
    let present = temporary.join("present.txt");
    fs::write(&present, b"present").unwrap();
    let missing = temporary.join("missing.txt");

    for inputs in [vec![present, missing], vec![archive.clone()]] {
        let mut append = sender_command();
        add_recipient(&mut append, "sender");
        add_recipient(&mut append, "recipient1");
        let output = append
            .arg("append")
            .arg("files")
            .arg("--file")
            .arg(&archive)
            .args(inputs)
            .output()
            .unwrap();
        let message = stderr(&output);
        assert!(!output.status.success());
        assert!(!message.contains("panicked"), "{message}");
        assert_eq!(fs::read(&archive).unwrap(), original);
    }
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn append_cli_reports_missing_input_without_mutating_the_archive() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let original = fs::read(&archive).unwrap();
    let input = temporary.join("missing.txt");
    let mut append = sender_command();
    add_recipient(&mut append, "sender");
    add_recipient(&mut append, "recipient1");

    let output = append
        .arg("append")
        .arg("files")
        .arg("--file")
        .arg(&archive)
        .arg(&input)
        .output()
        .unwrap();

    let message = stderr(&output);
    assert!(!output.status.success());
    assert!(message.contains("Filesystem Error"), "{message}");
    assert!(!message.contains("panicked"), "{message}");
    assert_eq!(fs::read(&archive).unwrap(), original);
    let _ = fs::remove_dir_all(temporary);
}

#[cfg(unix)]
#[test]
fn append_cli_reports_lock_contention_without_mutation() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let original = fs::read(&archive).unwrap();
    let input = temporary.join("locked.txt");
    fs::write(&input, b"locked cli payload").unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&archive)
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let mut append = sender_command();
    add_recipient(&mut append, "sender");
    add_recipient(&mut append, "recipient1");

    let output = append
        .arg("append")
        .arg("files")
        .arg("--file")
        .arg(&archive)
        .arg(&input)
        .output()
        .unwrap();
    let message = stderr(&output);

    assert!(!output.status.success());
    assert!(message.contains("locked by another cooperating writer"));
    assert!(!message.contains("panicked"), "{message}");
    assert_eq!(fs::read(&archive).unwrap(), original);
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn append_cli_rejects_a_non_archive_target_without_panicking_or_mutating_archives() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let original = fs::read(&archive).unwrap();
    let target = temporary.join("not-an-archive.txt");
    let target_original = b"not an archive";
    fs::write(&target, target_original).unwrap();
    let input = temporary.join("input.txt");
    fs::write(&input, b"cli input payload").unwrap();
    let mut append = sender_command();
    add_recipient(&mut append, "sender");
    add_recipient(&mut append, "recipient1");

    let output = append
        .arg("append")
        .arg("files")
        .arg("--file")
        .arg(&target)
        .arg(&input)
        .output()
        .unwrap();
    let message = stderr(&output);

    assert!(!output.status.success());
    assert!(message.contains("Filesystem Error"), "{message}");
    assert!(!message.contains("panicked"), "{message}");
    assert_eq!(fs::read(&archive).unwrap(), original);
    assert_eq!(fs::read(&target).unwrap(), target_original);
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn append_files_block_options_round_trip_and_conflicts_leave_the_archive() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let input = temporary.join("options.txt");
    fs::write(&input, b"appended with block options").unwrap();

    let mut conflict = sender_command();
    add_recipient(&mut conflict, "sender");
    let original = fs::read(&archive).unwrap();
    let output = conflict
        .args(["append", "files", "--file"])
        .arg(&archive)
        .args(["--block-size", "1024", "--cdc", "64,256,1024"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot be used with"));
    assert_eq!(fs::read(&archive).unwrap(), original);

    let mut append = sender_command();
    add_recipient(&mut append, "sender");
    add_recipient(&mut append, "recipient1");
    let output = append
        .args(["append", "files", "--file"])
        .arg(&archive)
        .args([
            "--block-size",
            "8",
            "--unique-keys",
            "--cipher",
            "aes-256-gcm",
        ])
        .arg(&input)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let read = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .args(["read", "data"])
        .arg(&archive)
        .arg("options.txt")
        .output()
        .unwrap();
    assert!(read.status.success(), "{}", stderr(&read));
    assert_eq!(read.stdout, b"appended with block options");
    let _ = fs::remove_dir_all(temporary);
}
