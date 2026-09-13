use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMPORARY: AtomicUsize = AtomicUsize::new(0);

fn workspace_file(path: &str) -> String {
    format!(
        "{}/../pithos_lib/tests/data/{path}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn temporary() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pithos-cli-create-{}-{}",
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

fn create_command(output: &std::path::Path, input: &std::path::Path) -> Command {
    let private = workspace_file("keys/sender_private.pem");
    let public = workspace_file("keys/recipient1_public.pem");
    let mut command = command();
    command
        .arg("--secret-key")
        .arg(private)
        .arg("--public-keys")
        .arg(public)
        .arg("--output")
        .arg(output)
        .arg("create")
        .arg(input);
    command
}

#[test]
fn create_reports_missing_keys_and_invalid_cdc() {
    let temporary = temporary();
    let input = temporary.join("input.txt");
    let missing_recipient_output = temporary.join("missing-recipient.pith");
    let invalid_cdc_output = temporary.join("invalid-cdc.pith");
    fs::write(&input, b"input").unwrap();
    let private = workspace_file("keys/sender_private.pem");
    let public = workspace_file("keys/recipient1_public.pem");
    assert!(
        !command()
            .args([
                "--secret-key",
                &private,
                "--output",
                missing_recipient_output.to_str().unwrap(),
                "create",
                input.to_str().unwrap(),
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(!missing_recipient_output.exists());
    assert!(
        !command()
            .args([
                "--secret-key",
                &private,
                "--public-keys",
                &public,
                "--output",
                invalid_cdc_output.to_str().unwrap(),
                "create",
                "--cdc",
                "8,4,16",
                input.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(!invalid_cdc_output.exists());
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn plain_create_and_every_read_subcommand_work_without_keys() {
    let temporary = temporary();
    let input = temporary.join("input.txt");
    let archive = temporary.join("plain.pith");
    fs::write(&input, b"plain cli content").unwrap();
    assert!(
        command()
            .arg("--output")
            .arg(&archive)
            .arg("create")
            .arg("--plain")
            .arg("--cdc")
            .arg("64,256,1024")
            .arg(&input)
            .status()
            .unwrap()
            .success()
    );

    for arguments in [
        vec!["read", "list", archive.to_str().unwrap()],
        vec!["read", "info", archive.to_str().unwrap(), "input.txt"],
        vec!["read", "directory", archive.to_str().unwrap()],
    ] {
        assert!(command().args(arguments).status().unwrap().success());
    }
    let data = command()
        .args(["read", "data", archive.to_str().unwrap(), "input.txt"])
        .output()
        .unwrap();
    assert!(data.status.success());
    assert_eq!(data.stdout, b"plain cli content");

    let extracted = temporary.join("extracted");
    fs::create_dir(&extracted).unwrap();
    assert!(
        command()
            .arg("--output")
            .arg(&extracted)
            .args(["read", "all"])
            .arg(&archive)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(extracted.join("input.txt")).unwrap(),
        b"plain cli content"
    );
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn plain_create_rejects_secret_and_public_key_options() {
    let temporary = temporary();
    let input = temporary.join("input");
    fs::write(&input, b"input").unwrap();
    let private = workspace_file("keys/sender_private.pem");
    let public = workspace_file("keys/recipient1_public.pem");
    for (index, key_args) in [
        vec!["--secret-key", private.as_str()],
        vec!["--public-keys", public.as_str()],
    ]
    .into_iter()
    .enumerate()
    {
        let output = temporary.join(format!("conflict-{index}.pith"));
        let result = command()
            .args(key_args)
            .arg("--output")
            .arg(&output)
            .arg("create")
            .arg("--plain")
            .arg(&input)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(
            String::from_utf8(result.stderr)
                .unwrap()
                .contains("conflict")
        );
        assert!(!output.exists());
    }
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn encrypted_archives_list_but_do_not_read_without_a_key() {
    let temporary = temporary();
    let input = temporary.join("encrypted.txt");
    let archive = temporary.join("encrypted.pith");
    fs::write(&input, b"encrypted").unwrap();
    assert!(create_command(&archive, &input).status().unwrap().success());

    let listing = command()
        .args(["read", "list", archive.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(listing.status.success());
    assert!(
        String::from_utf8(listing.stdout)
            .unwrap()
            .contains("available: false")
    );

    let read = command()
        .args(["read", "data", archive.to_str().unwrap(), "encrypted.txt"])
        .output()
        .unwrap();
    assert!(!read.status.success());
    assert!(
        String::from_utf8(read.stderr)
            .unwrap()
            .contains("unavailable")
    );
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn create_reports_filesystem_errors_and_produces_a_readable_archive() {
    let temporary = temporary();
    let private = workspace_file("keys/sender_private.pem");
    let public = workspace_file("keys/recipient1_public.pem");
    let output = temporary.join("archive.pith");
    assert!(
        !command()
            .args([
                "--secret-key",
                &private,
                "--public-keys",
                &public,
                "--output",
                output.to_str().unwrap(),
                "create",
                temporary.join("missing").to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(!output.exists());
    let input = temporary.join("input.txt");
    fs::write(&input, b"created by cli").unwrap();
    assert!(
        command()
            .args([
                "--secret-key",
                &private,
                "--public-keys",
                &public,
                "--output",
                output.to_str().unwrap(),
                "create",
                input.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(output.exists());
    assert!(
        command()
            .args([
                "--secret-key",
                &workspace_file("keys/recipient1_private.pem"),
                "read",
                "list",
                output.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn create_preflights_keys_recipients_and_all_cdc_bounds() {
    use fastcdc::v2020::{
        AVERAGE_MAX, AVERAGE_MIN, MAXIMUM_MAX, MAXIMUM_MIN, MINIMUM_MAX, MINIMUM_MIN,
    };

    let temporary = temporary();
    let input = temporary.join("input");
    fs::write(&input, b"input").unwrap();
    let private = workspace_file("keys/sender_private.pem");
    let public = workspace_file("keys/recipient1_public.pem");

    let missing_sender = temporary.join("missing-sender.pith");
    assert!(
        !command()
            .arg("--public-keys")
            .arg(&public)
            .arg("--output")
            .arg(&missing_sender)
            .arg("create")
            .arg(&input)
            .status()
            .unwrap()
            .success()
    );
    assert!(!missing_sender.exists());

    let duplicate_recipient = temporary.join("duplicate-recipient.pith");
    assert!(
        !command()
            .arg("--secret-key")
            .arg(&private)
            .arg("--public-keys")
            .arg(&public)
            .arg("--public-keys")
            .arg(&public)
            .arg("--output")
            .arg(&duplicate_recipient)
            .arg("create")
            .arg(&input)
            .status()
            .unwrap()
            .success()
    );
    assert!(!duplicate_recipient.exists());

    for (index, (min, avg, max)) in [
        (MINIMUM_MIN - 1, AVERAGE_MIN, MAXIMUM_MIN),
        (MINIMUM_MAX + 1, AVERAGE_MAX, MAXIMUM_MAX),
        (MINIMUM_MIN, AVERAGE_MIN - 1, MAXIMUM_MIN),
        (MINIMUM_MIN, AVERAGE_MAX + 1, MAXIMUM_MAX),
        (MINIMUM_MIN, AVERAGE_MIN, MAXIMUM_MIN - 1),
        (MINIMUM_MIN, AVERAGE_MIN, MAXIMUM_MAX + 1),
    ]
    .into_iter()
    .enumerate()
    {
        let output = temporary.join(format!("invalid-cdc-{index}.pith"));
        assert!(
            !create_command(&output, &input)
                .arg("--cdc")
                .arg(format!("{min},{avg},{max}"))
                .status()
                .unwrap()
                .success()
        );
        assert!(!output.exists());
    }
    let _ = fs::remove_dir_all(temporary);
}

#[test]
fn create_never_clobbers_existing_output_and_removes_post_creation_failure() {
    let temporary = temporary();
    let input = temporary.join("input");
    fs::write(&input, b"input").unwrap();
    let existing = temporary.join("existing.pith");
    let original = b"do not replace";
    fs::write(&existing, original).unwrap();
    assert!(
        !create_command(&existing, &input)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::read(&existing).unwrap(), original);

    let created_then_failed = temporary.join("created-then-failed.pith");
    assert!(
        !create_command(&created_then_failed, &input)
            .env("PITHOS_TEST_FAIL_AFTER_CREATE", "1")
            .status()
            .unwrap()
            .success()
    );
    assert!(!created_then_failed.exists());
    let _ = fs::remove_dir_all(temporary);
}

#[cfg(unix)]
#[test]
fn create_rejects_symlinked_output_parent_before_publication() {
    use std::os::unix::fs::symlink;

    let temporary = temporary();
    let input = temporary.join("input");
    let outside = temporary.join("outside");
    let redirect = temporary.join("redirect");
    fs::write(&input, b"input").unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, &redirect).unwrap();

    let output = redirect.join("archive.pith");
    assert!(!create_command(&output, &input).status().unwrap().success());
    assert!(!outside.join("archive.pith").exists());
    let _ = fs::remove_dir_all(temporary);
}

#[cfg(unix)]
#[test]
fn create_rejects_non_utf8_paths_and_unsafe_symlinks_before_publication() {
    use std::os::unix::ffi::OsStringExt;

    let temporary = temporary();
    let output = temporary.join("output.pith");
    let invalid_path = temporary.join(std::ffi::OsString::from_vec(b"invalid-\xff".to_vec()));
    fs::write(&invalid_path, b"input").unwrap();
    assert!(
        !create_command(&output, &invalid_path)
            .status()
            .unwrap()
            .success()
    );
    assert!(!output.exists());

    let invalid_target = temporary.join("invalid-target");
    std::os::unix::fs::symlink(
        std::path::Path::new(&std::ffi::OsString::from_vec(b"target-\xff".to_vec())),
        &invalid_target,
    )
    .unwrap();
    assert!(
        !create_command(&output, &invalid_target)
            .status()
            .unwrap()
            .success()
    );
    assert!(!output.exists());

    let unsafe_link = temporary.join("unsafe");
    std::os::unix::fs::symlink("/outside", &unsafe_link).unwrap();
    assert!(
        !create_command(&output, &unsafe_link)
            .status()
            .unwrap()
            .success()
    );
    assert!(!output.exists());
    let _ = fs::remove_dir_all(temporary);
}

#[cfg(unix)]
#[test]
fn create_rejects_unreadable_input_before_publication_when_permissions_apply() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = temporary();
    let input = temporary.join("unreadable");
    let output = temporary.join("output.pith");
    fs::write(&input, b"input").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&input).is_err() {
        assert!(!create_command(&output, &input).status().unwrap().success());
        assert!(!output.exists());
    }
    fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
    let _ = fs::remove_dir_all(temporary);
}
