mod io;
pub mod utils;

use crate::io::utils::{load_private_key_from_pem, load_public_key_from_pem};
use clap::{Parser, Subcommand, ValueEnum};
use pithos_lib::error::PithosError;
use pithos_lib::helpers::x25519_keys::{
    generate_private_key, private_key_to_pem_bytes, public_key_to_pem_bytes,
};
use pithos_lib::io::pithosreader::PithosReaderSimple;
use pithos_lib::io::pithoswriter::{InputFile, PithosWriter};
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use std::path::PathBuf;
use thiserror::Error;
use tracing::dispatcher::SetGlobalDefaultError;
use tracing_subscriber::prelude::*;
use utils::conversion::{evaluate_log_level, parse_cdc_input, parse_range_input};
use x25519_dalek::PublicKey;

#[derive(Clone, Default, ValueEnum)]
enum KeyFormat {
    #[default]
    Openssl, // PKCS#8 encoded key in PEM format
             //Crypt4gh, // Additional encryption of key
             //Raw,      // Only key bytes
}

#[derive(Clone, Default, ValueEnum)]
enum ExportFormat {
    //Pithos,
    #[default]
    Crypt4gh,
    //RoCrate,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Set the log level
    #[arg(long, value_name = "LOG_LEVEL", default_value = "Info")]
    log_level: Option<String>,

    /// Display additional logging information (file, line number, target)
    #[arg(short, long)]
    verbose: bool,

    /// Set the log file
    #[arg(long, value_name = "LOG_FILE")]
    log_file: Option<PathBuf>,

    /// Output destination; Default is stdout
    #[arg(global = true, short, long)]
    output: Option<PathBuf>,

    /// Private keys for encryption/decryption
    #[arg(global = true, short, long, alias = "sk")]
    secret_key: Option<PathBuf>, // File paths; if None -> Default file: ~/.pithos/sec_key.pem

    /// Public keys for encryption/decryption
    #[arg(global = true, short, long, alias = "pk")]
    public_keys: Option<Vec<PathBuf>>, // File paths; if None -> Default file: ~/.pithos/pub_key.pem

    /// Subcommands
    #[command(subcommand)]
    command: PithosCommands,
}

#[derive(Subcommand)]
enum PithosCommands {
    /// Create a Pithos file from some input
    Create {
        /*
        /// Expect file metadata next to input files with '<input-file>.meta'
        #[arg(short, long)]
        metadata: bool,
        /// Check for files containing custom ranges as CSV
        #[arg(long, group = "ranges")]
        range_files: bool,
        /// Automagically generates custom ranges for supported file formats: FASTA, FASTQ
        #[arg(long, group = "ranges")]
        auto_generate_ranges: bool,
        /// Generates custom ranges according to the provided regex
        #[arg(long, group = "ranges")]
        ranges_regex: Option<String>,
        /// Public keys of recipients
        #[arg(long)]
        reader_public_keys: Option<Vec<PathBuf>>, // Iterate files and parse all keys
        */
        /// Set values for content-defined chunking
        #[arg(long="cdc", value_parser=parse_cdc_input, value_name = "MIN,AVG,MAX")]
        cdc: Option<(u32, u32, u32)>,
        /// Input files
        #[arg(value_name = "FILES")]
        files: Vec<PathBuf>,
    },
    /// Modify the Pithos footer
    Append {
        /// Subcommands
        #[command(subcommand)]
        command: AppendCommands,
    },
    /// Read pithos file
    Read {
        /// Subcommands
        #[command(subcommand)]
        read_command: ReadCommands,
    },
    /// Create keypair
    Keypair {
        /// Key format; Default is PKCS#8 encoded x25519 keypair in PEM format
        #[arg(short, long)]
        format: Option<KeyFormat>,
        /// Key file prefix (e.g. sender -> sender.<sec/pub>.pem)
        #[arg(short, long)]
        prefix: Option<String>,
    },
    /// Export a Pithos file into another compatible file format
    Export {
        #[arg(short, long, value_enum)]
        format: ExportFormat,
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Path in Pithos file
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum ReadCommands {
    /// Read the metadata of a specific file
    Info {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Path in Pithos file
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// List paths of all available files
    List {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read data of all available files
    All {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read data of a specific file
    Data {
        /// Path to Pithos file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Path in Pithos file
        #[arg(value_name = "PATHS")]
        paths: Vec<PathBuf>,
        /// Specific byte ranges in the file
        #[arg(short, long, value_parser=parse_range_input, value_delimiter=',', value_name = "START:END,...")]
        ranges: Option<Vec<Range<u64>>>,
    },
    /// Read the directory
    Directory {
        /// Input file
        ///
        ///ToDo: Filter to display only specific entries of the ToC?
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /*
    Search {
        /// Extract search hits in output target
        #[arg(short, long)]
        extract: bool,
        /// Fuzzy search or exact
        #[arg(short, long)]
        fuzzy_search: bool,
        /// Input file
        ///ToDo: Filter to display only specific entries of the ToC?
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    */
}

#[derive(Subcommand)]
enum AppendCommands {
    /// Add one or multiple readers to the encryption section
    Readers {
        // List of file ids the readers shall get access to
        #[arg(short, long)]
        ids: Option<Vec<u64>>,
        /// Path to Pithos file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Add files to an existing Pithos container
    Files {
        /// Path to Pithos file
        #[arg(short, long, value_name = "PITHOS FILE")]
        file: PathBuf,
        /// Input files
        #[arg(value_name = "FILES")]
        files: Vec<PathBuf>,
    },
}

#[derive(Error, Debug)]
pub enum PithosCliError {
    #[error("Writer Error: {0}")]
    TracingError(#[from] SetGlobalDefaultError),
    #[error("Invalid argument: {0}")]
    InvalidArgumentError(String),
    #[error("Pithos Error: {0}")]
    PithosError(#[from] PithosError),
}

#[tracing::instrument(level = "trace", skip())]
fn main() -> Result<(), PithosCliError> {
    // Parse CLI parameter input
    let cli = Cli::parse();

    // Initialize tracing logger
    let logging_filter = evaluate_log_level(cli.log_level);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_file(cli.verbose)
        .with_line_number(cli.verbose)
        .with_target(cli.verbose)
        .with_filter(logging_filter);

    tracing_subscriber::registry().with(fmt_layer).init();

    // Evaluate subcommand
    match cli.command {
        PithosCommands::Read { read_command } => match read_command {
            ReadCommands::Info { file, path } => {
                let path_str = path
                    .to_str()
                    .expect("No inner path provided or path contains invalid UTF-8");
                let key = load_private_key_from_pem(
                    &cli.secret_key
                        .clone()
                        .expect("Private key expected to read directory"),
                )?;
                let mut reader = PithosReaderSimple::new_with_key(&file, key)?;
                let (directory, _) = reader.read_directory()?;
                match directory.get_file_by_path(path_str) {
                    Some(entry) => println!("{entry}"),
                    None => Err(PithosError::FileNotFound(path_str.to_string()))?,
                }
            }
            ReadCommands::List { file } => {
                let key = load_private_key_from_pem(
                    &cli.secret_key
                        .clone()
                        .expect("Private key expected to read directory"),
                )?;
                let mut reader = PithosReaderSimple::new_with_key(&file, key)?;
                let (directory, _) = reader.read_directory()?;
                directory
                    .files
                    .iter()
                    .for_each(|(id, path, fe)| println!("{} {:?} {}", id, fe.file_type, path))
            }
            ReadCommands::All { file } => {
                let key = load_private_key_from_pem(
                    &cli.secret_key
                        .clone()
                        .expect("Private key expected to read directory"),
                )?;
                let mut reader = PithosReaderSimple::new_with_key(&file, key)?;
                let (directory, _) = reader.read_directory()?;

                for path in directory.files.get_paths_ref() {
                    reader.read_file(path, &directory, cli.output.as_ref(), None)?;
                }
            }
            ReadCommands::Data {
                file,
                paths,
                ranges,
            } => {
                let key = load_private_key_from_pem(
                    &cli.secret_key
                        .clone()
                        .expect("Private key expected to read directory"),
                )?;

                let mut reader = PithosReaderSimple::new_with_key(&file, key)?;
                let (directory, _) = reader.read_directory()?;

                for path in paths {
                    reader.read_file(
                        path.to_str()
                            .expect("No inner path provided or path contains invalid UTF-8"),
                        &directory,
                        cli.output.as_ref(),
                        ranges.clone(),
                    )?;
                }
            }
            ReadCommands::Directory { file } => {
                let key = load_private_key_from_pem(
                    &cli.secret_key
                        .clone()
                        .expect("Private key expected to read directory"),
                )?;
                let mut reader = PithosReaderSimple::new_with_key(&file, key)?;

                println!("{:#?}", reader.read_directory()?);
            }
        },
        PithosCommands::Create { cdc, files } => {
            if files.is_empty() {
                return Err(PithosCliError::InvalidArgumentError(
                    "No files provided".to_string(),
                ));
            }

            let output = if let Some(outfile) = cli.output {
                File::create(outfile).map_err(PithosError::Io)?
            } else {
                // Default outfile
                println!("No outfile specified, writing output to \"/tmp/out.pithos\""); //TODO: Replace with tracing::warn!()
                File::create("/tmp/out.pithos").map_err(PithosError::Io)?
            };

            let sender_key = load_private_key_from_pem(
                &cli.secret_key
                    .clone()
                    .expect("Private key expected to create Pithos file"),
            )?;
            let reader_keys: Result<Vec<PublicKey>, PithosError> = cli
                .public_keys
                .expect("At least one recipient expected")
                .iter()
                .map(load_public_key_from_pem)
                .collect();

            let input_files: Result<Vec<InputFile>, PithosError> =
                files.iter().map(InputFile::try_from).collect();
            let mut writer = PithosWriter::new(sender_key, reader_keys?, cdc, Box::new(output))?;

            tracing::info!("Start creating Pithos file");
            writer
                .write_file_header()
                .map_err(PithosError::Serialization)?;
            writer.process_input_files(input_files?)?;
            writer.write_directory()?;
        }
        PithosCommands::Keypair { prefix, .. } => {
            let private_key = generate_private_key().map_err(PithosError::Crypt)?;
            let public_key = PublicKey::from(&private_key);
            let prefix = prefix.unwrap_or("pithos_key".to_string());

            // Write output
            let (mut sec_output, mut pub_output): (Box<dyn Write>, Box<dyn Write>) =
                if let Some(dest) = cli.output {
                    let (sec_target, pub_target) = if dest.is_dir() {
                        (
                            &dest.join(format!("{prefix}.sec.pem")),
                            &dest.join(format!("{prefix}.pub.pem")),
                        )
                    } else {
                        (&dest, &dest)
                    };
                    (
                        Box::new(File::create(sec_target).map_err(PithosError::Io)?),
                        Box::new(File::create(pub_target).map_err(PithosError::Io)?),
                    )
                } else {
                    (Box::new(std::io::stdout()), Box::new(std::io::stdout()))
                };

            sec_output
                .write_all(&private_key_to_pem_bytes(&private_key).map_err(PithosError::Crypt)?)
                .map_err(PithosError::Io)?;
            pub_output
                .write_all(&public_key_to_pem_bytes(&public_key).map_err(PithosError::Crypt)?)
                .map_err(PithosError::Io)?;
        }
        PithosCommands::Append { command } => {
            match command {
                AppendCommands::Readers { file, ids } => {
                    let sender_key = load_private_key_from_pem(
                        &cli.secret_key
                            .clone()
                            .expect("Private key expected to append to Pithos file"),
                    )?;
                    let reader_keys_result: Result<Vec<PublicKey>, PithosError> = cli
                        .public_keys
                        .expect("At least one recipient expected")
                        .iter()
                        .map(load_public_key_from_pem)
                        .collect();
                    let reader_keys = reader_keys_result?;

                    let mut reader = PithosReaderSimple::new_with_key(&file, sender_key.clone())?;
                    let (directory, _) = reader.read_directory()?;

                    let mut fes = vec![];
                    if let Some(ids) = ids {
                        for id in ids {
                            fes.push((
                                id,
                                directory
                                    .get_file_by_id(id)
                                    .ok_or(PithosError::FileNotFound(format!(
                                        "File with id {id} not available."
                                    )))?,
                            ));
                        }
                    }
                    if fes.is_empty() {
                        return Err(PithosCliError::InvalidArgumentError(
                            "No available id or path provided".to_string(),
                        ));
                    }

                    let mut writer = PithosWriter::new_from_file(
                        sender_key.clone(),
                        reader_keys.clone(),
                        None,
                        &file,
                    )?;

                    let directory = writer.get_directory_mut();
                    for (id, fe) in fes {
                        let enc_key =
                            directory
                                .get_file_encryption_key(id)
                                .ok_or(PithosError::Other(format!(
                                    "Could not extract encryption key for file {id}"
                                )))?;

                        for reader in &reader_keys {
                            directory.add_file_to_recipient(&sender_key, reader, (id, enc_key))?;
                        }
                    }

                    writer.write_directory()?
                }
                AppendCommands::Files { file, files } => {
                    let sender_key = load_private_key_from_pem(
                        &cli.secret_key
                            .clone()
                            .expect("Private key expected to append to Pithos file"),
                    )?;
                    let reader_keys: Result<Vec<PublicKey>, PithosError> = cli
                        .public_keys
                        .expect("At least one recipient expected")
                        .iter()
                        .map(load_public_key_from_pem)
                        .collect();

                    let append_files: Result<Vec<InputFile>, PithosError> =
                        files.iter().map(InputFile::try_from).collect();

                    let mut writer =
                        PithosWriter::new_from_file(sender_key, reader_keys?, None, &file)?;

                    // Append files
                    writer.process_input_files(append_files?)?;
                    writer.write_directory()?;
                }
            }

            unimplemented!()
        }
        PithosCommands::Export { file, path, .. } => {
            let path_str = path
                .to_str()
                .expect("No inner path provided or path contains invalid UTF-8");
            let sender_key = load_private_key_from_pem(
                &cli.secret_key
                    .clone()
                    .expect("Private key expected to create Pithos file"),
            )?;
            let reader_keys: Result<Vec<PublicKey>, PithosError> = cli
                .public_keys
                .expect("At least one recipient expected")
                .iter()
                .map(load_public_key_from_pem)
                .collect();

            let mut reader = PithosReaderSimple::new_with_key(&file, sender_key)?;
            let (directory, _) = reader.read_directory()?;

            // Write output
            let output_target: Box<dyn Write> = if let Some(dest) = cli.output {
                Box::new(std::fs::File::create(dest).map_err(PithosError::Io)?)
            } else {
                Box::new(std::io::stdout())
            };

            reader.read_file_to_crypt4gh(
                path_str,
                &directory,
                reader_keys?,
                Some(output_target),
            )?;
        }
    }

    Ok(())
}
