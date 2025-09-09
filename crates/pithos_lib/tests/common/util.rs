use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
use pithos_lib::io::pithoswriter::{Content, InputFile, PithosWriter};
use pithos_lib::model::structs::FileType;
use std::fs::{File, Permissions, create_dir_all, read_to_string, set_permissions};
use std::io::copy;
use std::path::PathBuf;
use tempfile::TempDir;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn load_test_keys() -> (StaticSecret, PublicKey, PublicKey) {
    // Read sender private key
    let sender_pem_content = read_to_string("tests/data/keys/sender_private.pem").unwrap();
    let writer_key = private_key_from_pem_bytes(sender_pem_content.as_bytes()).unwrap();

    // Read recipient 1 public key
    let recipient1_pem_content = read_to_string("tests/data/keys/recipient1_public.pem").unwrap();
    let reader_key_01 = public_key_from_pem_bytes(recipient1_pem_content.as_bytes()).unwrap();

    // Read recipient 2 public key
    let recipient2_pem_content = read_to_string("tests/data/keys/recipient2_public.pem").unwrap();
    let reader_key_02 = public_key_from_pem_bytes(recipient2_pem_content.as_bytes()).unwrap();

    (writer_key, reader_key_01, reader_key_02)
}

pub fn write_dummy_pithos(temp_dir: &TempDir, multifile: bool, metadata: bool) -> PathBuf {
    // Dummy file(s)
    let mut input_files = vec![InputFile {
        file_type: FileType::Data,
        file_path: "t8.shakespeare.txt".to_string(),
        data: Content::File("tests/data/t8.shakespeare.sample.txt".to_string()),
        metadata: if metadata {
            Some(Content::Raw(r#"{"foo":"bar"}"#.to_string()))
        } else {
            None
        },
        encrypt: true,
        compression_level: Some(3),
    }];

    if multifile {
        input_files.push(InputFile {
            file_type: FileType::Data,
            file_path: "SRR33138449.fastq".to_string(),
            data: Content::File("tests/data/SRR33138449.sample.fastq".to_string()),
            metadata: if metadata {
                Some(Content::Raw(r#"{"bar":"baz"}"#.to_string()))
            } else {
                None
            },
            encrypt: true,
            compression_level: Some(3),
        })
    }

    // Load dummy keys
    let (sender_key, r1_key, r2_key) = load_test_keys();

    // Prepare input for writer
    let file_path = temp_dir.path().join("dummy.pith");
    let outfile = File::create(&file_path).unwrap();
    let mut writer =
        PithosWriter::new(sender_key, vec![r1_key, r2_key], None, Box::new(outfile)).unwrap();

    // Process
    writer.write_file_header().unwrap();
    writer.process_input_files(input_files).unwrap();
    writer.write_directory().unwrap();

    file_path
}

pub fn extract_zip(zip_file: File, out_dir: &PathBuf) {
    let mut archive = zip::ZipArchive::new(zip_file).unwrap();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let file_path = match file.enclosed_name() {
            Some(path) => path,
            None => continue,
        };
        let outpath = out_dir.join(file_path);

        {
            let comment = file.comment();
            if !comment.is_empty() {
                println!("File {i} comment: {comment}");
            }
        }

        if file.is_dir() {
            println!("File {} extracted to \"{}\"", i, outpath.display());
            create_dir_all(&outpath).unwrap();
        } else {
            println!(
                "File {} extracted to \"{}\" ({} bytes)",
                i,
                outpath.display(),
                file.size()
            );
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    create_dir_all(p).unwrap();
                }
            }
            let mut outfile = File::create(&outpath).unwrap();
            copy(&mut file, &mut outfile).unwrap();
        }

        // Get and Set permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if let Some(mode) = file.unix_mode() {
                set_permissions(&outpath, Permissions::from_mode(mode)).unwrap();
            }
        }
    }
}
