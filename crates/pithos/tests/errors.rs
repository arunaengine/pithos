use std::os::unix::fs::symlink;
use std::process::{Command, Output, Stdio};

fn workspace_file(path: &str) -> String {
    format!(
        "{}/../pithos_lib/tests/data/{path}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pithos"))
}

fn temporary_directory(label: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("pithos-cli-errors-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir(&path).unwrap();
    path
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn run_with_closed_stdout(mut command: Command) -> Output {
    let mut child = command
        .env("PITHOS_TEST_DELAY_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    child.wait_with_output().unwrap()
}

fn assert_broken_pipe(label: &str, output: &Output) {
    let message = stderr(output);
    assert!(!output.status.success(), "{label} unexpectedly succeeded");
    assert!(!message.contains("panicked"), "{label}: {message}");
    assert!(
        message.contains("Broken pipe") || message.contains("broken pipe"),
        "{label}: {message}"
    );
}

#[test]
fn export_without_recipients_returns_an_error_without_panicking() {
    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/sender_private.pem"))
        .arg("export")
        .arg("--format")
        .arg("crypt4gh")
        .arg("missing.pith")
        .arg("entry")
        .output()
        .unwrap();

    let stderr = stderr(&output);
    assert!(!output.status.success());
    assert!(stderr.contains("at least one recipient key is required"));
    assert!(!stderr.contains("panicked"));
    assert!(!stderr.contains("At least one recipient expected"));
}

#[test]
fn invalid_log_level_returns_an_error_without_panicking() {
    let output = command()
        .arg("--log-level")
        .arg("not-a-log-level[")
        .arg("keypair")
        .output()
        .unwrap();

    let stderr = stderr(&output);
    assert!(!output.status.success());
    assert!(stderr.contains("invalid log level"));
    assert!(!stderr.contains("panicked"));
}

#[test]
fn missing_private_key_error_keeps_operation_and_path_context() {
    let temporary = temporary_directory("missing-key");
    let missing_key = temporary.join("missing-private.pem");
    let output = command()
        .arg("--secret-key")
        .arg(&missing_key)
        .arg("read")
        .arg("list")
        .arg(temporary.join("missing.pith"))
        .output()
        .unwrap();

    let message = stderr(&output);
    assert!(!output.status.success());
    assert!(message.contains("load private key"), "{message}");
    assert!(message.contains(missing_key.to_str().unwrap()), "{message}");
    assert!(!message.contains("panicked"));
    let _ = std::fs::remove_dir_all(temporary);
}

#[test]
fn invalid_cdc_component_names_the_component_instead_of_a_range() {
    let temporary = temporary_directory("invalid-cdc");
    let input = temporary.join("input");
    std::fs::write(&input, b"content").unwrap();
    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/sender_private.pem"))
        .arg("--public-keys")
        .arg(workspace_file("keys/recipient1_public.pem"))
        .arg("create")
        .arg("--cdc")
        .arg("invalid,256,1024")
        .arg(input)
        .output()
        .unwrap();

    let message = stderr(&output);
    assert!(!output.status.success());
    assert!(message.contains("CDC minimum"), "{message}");
    assert!(!message.contains("range start"), "{message}");
    assert!(!message.contains("panicked"));
    let _ = std::fs::remove_dir_all(temporary);
}

#[test]
fn oversized_private_key_is_rejected_before_full_allocation() {
    let temporary = temporary_directory("oversized-key");
    let oversized = temporary.join("oversized-private.pem");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    let output = command()
        .arg("--secret-key")
        .arg(&oversized)
        .arg("read")
        .arg("list")
        .arg(temporary.join("missing.pith"))
        .output()
        .unwrap();

    let message = stderr(&output);
    assert!(!output.status.success());
    assert!(message.contains("private key file exceeds"), "{message}");
    assert!(message.contains(oversized.to_str().unwrap()), "{message}");
    assert!(!message.contains("panicked"));
    let _ = std::fs::remove_dir_all(temporary);
}

#[test]
fn private_key_loading_rejects_symbolic_links() {
    let temporary = temporary_directory("key-symlink");
    let key_link = temporary.join("private.pem");
    symlink(workspace_file("keys/recipient1_private.pem"), &key_link).unwrap();
    let output = command()
        .arg("--secret-key")
        .arg(&key_link)
        .arg("read")
        .arg("list")
        .arg(temporary.join("missing.pith"))
        .output()
        .unwrap();

    let message = stderr(&output);
    assert!(!output.status.success());
    assert!(message.contains("load private key"), "{message}");
    assert!(message.contains(key_link.to_str().unwrap()), "{message}");
    assert!(!message.contains("panicked"));
    let _ = std::fs::remove_dir_all(temporary);
}

#[test]
fn public_key_loading_rejects_symbolic_links() {
    let temporary = temporary_directory("public-key-symlink");
    let key_link = temporary.join("public.pem");
    let input = temporary.join("input");
    symlink(workspace_file("keys/recipient1_public.pem"), &key_link).unwrap();
    std::fs::write(&input, b"input").unwrap();
    let output = command()
        .arg("--secret-key")
        .arg(workspace_file("keys/sender_private.pem"))
        .arg("--public-keys")
        .arg(&key_link)
        .arg("--output")
        .arg(temporary.join("archive.pith"))
        .arg("create")
        .arg(input)
        .output()
        .unwrap();

    let message = stderr(&output);
    assert!(!output.status.success());
    assert!(message.contains("load public key"), "{message}");
    assert!(message.contains(key_link.to_str().unwrap()), "{message}");
    assert!(!message.contains("panicked"));
    let _ = std::fs::remove_dir_all(temporary);
}

#[test]
fn broken_stdout_returns_an_error_without_panicking() {
    let temporary = std::env::temp_dir().join(format!("pithos-cli-pipe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temporary);
    std::fs::create_dir(&temporary).unwrap();
    let input = temporary.join("input");
    let archive = temporary.join("archive.pith");
    std::fs::write(&input, b"pipe test").unwrap();
    assert!(
        command()
            .arg("--secret-key")
            .arg(workspace_file("keys/sender_private.pem"))
            .arg("--public-keys")
            .arg(workspace_file("keys/recipient1_public.pem"))
            .arg("--output")
            .arg(&archive)
            .arg("create")
            .arg(&input)
            .status()
            .unwrap()
            .success()
    );

    let mut read_directory = command();
    read_directory
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("read")
        .arg("directory")
        .arg(&archive);
    assert_broken_pipe("read directory", &run_with_closed_stdout(read_directory));

    let mut create = command();
    create
        .arg("--secret-key")
        .arg(workspace_file("keys/sender_private.pem"))
        .arg("--public-keys")
        .arg(workspace_file("keys/recipient1_public.pem"))
        .arg("create")
        .arg(&input);
    assert_broken_pipe("create", &run_with_closed_stdout(create));

    let mut read_data = command();
    read_data
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("read")
        .arg("data")
        .arg(&archive)
        .arg("input");
    assert_broken_pipe("read data", &run_with_closed_stdout(read_data));

    let mut keypair = command();
    keypair.arg("keypair");
    assert_broken_pipe("keypair", &run_with_closed_stdout(keypair));

    let mut export = command();
    export
        .arg("--secret-key")
        .arg(workspace_file("keys/recipient1_private.pem"))
        .arg("--public-keys")
        .arg(workspace_file("keys/recipient2_public.pem"))
        .arg("export")
        .arg("--format")
        .arg("crypt4gh")
        .arg(&archive)
        .arg("input");
    assert_broken_pipe("export", &run_with_closed_stdout(export));
    let _ = std::fs::remove_dir_all(temporary);
}
