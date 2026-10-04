use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
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
        "pithos-cli-output-safety-{}-{}",
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

fn create_archive(temporary: &Path) -> PathBuf {
    let first = temporary.join("first.txt");
    let second = temporary.join("second.txt");
    let archive = temporary.join("archive.pith");
    fs::write(&first, b"first content").unwrap();
    fs::write(&second, b"second content").unwrap();
    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/sender_private.pem"))
        .arg("--public-keys")
        .arg(workspace_file("keys/recipient1_public.pem"))
        .arg("--output")
        .arg(&archive)
        .arg("create")
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    archive
}

#[test]
fn read_data_never_clobbers_an_existing_output() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let output_path = temporary.join("existing");
    fs::write(&output_path, b"unchanged").unwrap();

    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("--output")
        .arg(&output_path)
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("first.txt")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read(&output_path).unwrap(), b"unchanged");
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn read_data_rejects_multiple_paths_with_one_file_output() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let output_path = temporary.join("ambiguous");

    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("--output")
        .arg(&output_path)
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("first.txt")
        .arg("second.txt")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!output_path.exists());
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn read_data_removes_staged_output_when_archive_copy_fails() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let output_path = temporary.join("incomplete");

    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("--output")
        .arg(&output_path)
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("missing.txt")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!output_path.exists());
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn crypt4gh_export_never_clobbers_an_existing_output() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let output_path = temporary.join("existing.c4gh");
    fs::write(&output_path, b"unchanged").unwrap();

    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("--public-keys")
        .arg(workspace_file("keys/recipient2_public.pem"))
        .arg("--output")
        .arg(&output_path)
        .arg("export")
        .arg("--format")
        .arg("crypt4gh")
        .arg(&archive)
        .arg("first.txt")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read(&output_path).unwrap(), b"unchanged");
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn read_output_rejects_symlinked_parent_components() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let outside = temporary.join("outside");
    fs::create_dir_all(outside.join("nested")).unwrap();
    let redirect = temporary.join("redirect");
    symlink(&outside, &redirect).unwrap();
    let output_path = redirect.join("nested/escaped-output");

    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("--output")
        .arg(&output_path)
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("first.txt")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!outside.join("nested/escaped-output").exists());
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn staged_output_publication_uses_the_retained_file_identity() {
    let source = include_str!("../src/main.rs");
    assert!(
        source.contains("AtFlags::EMPTY_PATH"),
        "publication must link the retained staged descriptor, not a replaceable temporary name"
    );
}

#[test]
fn crypt4gh_export_removes_staged_output_when_export_fails() {
    let temporary = temporary();
    let archive = create_archive(&temporary);
    let output_path = temporary.join("incomplete.c4gh");

    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("--public-keys")
        .arg(workspace_file("keys/recipient2_public.pem"))
        .arg("--output")
        .arg(&output_path)
        .arg("export")
        .arg("--format")
        .arg("crypt4gh")
        .arg(&archive)
        .arg("missing.txt")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!output_path.exists());
    let _ = fs::remove_dir_all(temporary);
}
