use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMPORARY: AtomicUsize = AtomicUsize::new(0);

fn temporary() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pithos-cli-keypair-{}-{}",
        std::process::id(),
        NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    path
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pithos"))
}

#[test]
fn keypair_private_file_is_created_with_mode_0600() {
    let temporary = temporary();
    let output = command()
        .arg("--output")
        .arg(&temporary)
        .arg("keypair")
        .arg("--prefix")
        .arg("secure")
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let mode = fs::metadata(temporary.join("secure.sec.pem"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn keypair_rejects_escaping_prefix_before_writing() {
    let temporary = temporary();
    let output_directory = temporary.join("keys");
    fs::create_dir(&output_directory).unwrap();
    let output = command()
        .arg("--output")
        .arg(&output_directory)
        .arg("keypair")
        .arg("--prefix")
        .arg("../escaped")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!temporary.join("escaped.sec.pem").exists());
    assert!(!temporary.join("escaped.pub.pem").exists());
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn keypair_writes_a_combined_no_clobber_file_with_private_permissions() {
    let temporary = temporary();
    let output_path = temporary.join("combined.pem");
    let output = command()
        .arg("--output")
        .arg(&output_path)
        .arg("keypair")
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let bytes = fs::read(&output_path).unwrap();
    let pem = String::from_utf8(bytes).unwrap();
    assert!(pem.contains("BEGIN PRIVATE KEY"));
    assert!(pem.contains("BEGIN PUBLIC KEY"));
    assert_eq!(
        fs::metadata(&output_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    fs::write(&output_path, b"unchanged").unwrap();
    let collision = command()
        .arg("--output")
        .arg(&output_path)
        .arg("keypair")
        .output()
        .unwrap();
    assert!(!collision.status.success());
    assert_eq!(fs::read(&output_path).unwrap(), b"unchanged");
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn keypair_does_not_follow_an_existing_private_key_symlink() {
    let temporary = temporary();
    let output_directory = temporary.join("keys");
    fs::create_dir(&output_directory).unwrap();
    let victim = temporary.join("victim");
    fs::write(&victim, b"unchanged").unwrap();
    symlink(&victim, output_directory.join("secure.sec.pem")).unwrap();

    let output = command()
        .arg("--output")
        .arg(&output_directory)
        .arg("keypair")
        .arg("--prefix")
        .arg("secure")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    let _ = fs::remove_dir_all(temporary);
}
