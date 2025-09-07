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
use std::io::Write;
use std::ops::Range;
use std::path::PathBuf;
use thiserror::Error;
use tracing::dispatcher::SetGlobalDefaultError;
use utils::conversion::{evaluate_log_level, parse_cdc_input, parse_range_input};
use x25519_dalek::PublicKey;

#[derive(Clone, Default, ValueEnum)]
enum KeyFormat {
    #[default]
    Openssl, // PKCS#8 encoded key in PEM format
    Crypt4gh, // Additional encryption of key
    Raw,      // Only key bytes
}

#[derive(Clone, Default, ValueEnum)]
enum ExportFormat {
    #[default]
    Pithos,
    Crypt4gh,
    RoCrate,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Optionally set the log level
    #[arg(long, value_name = "LOG_LEVEL", default_value = "Info")]
    log_level: Option<String>,

    /// Optionally set the log file
    #[arg(long, value_name = "LOG_FILE")]
    log_file: Option<PathBuf>,

    /// Output destination; Default is stdout
    #[arg(global = true, short, long)]
    output: Option<PathBuf>,

    /// Private keys for encryption/decryption
    #[arg(global = true, short, long, alias = "sk")]
    secret_keys: Option<PathBuf>, // File paths; if None -> Default file: ~/.pithos/sec_key.pem

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
    /// Read pithos file
    Read {
        /// Subcommands
        #[command(subcommand)]
        read_command: ReadCommands,
    },
    /// Create x25519
    CreateKeypair {
        /// Key format; Default is PKCS#8 encoded x25519 keypair in PEM format
        #[arg(short, long)]
        format: Option<KeyFormat>,
    },
    /// Modify the Pithos footer
    Modify {
        /// Subcommands
        #[command(subcommand)]
        command: Option<ModifyCommands>,
    },
    /// Export a Pithos file into another compatible file format
    Export {
        #[arg(short, long, value_enum)]
        format: Option<ExportFormat>,
    },
}

#[derive(Subcommand)]
enum ReadCommands {
    /// Read the metadata of the file
    Info {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Path in Pithos file
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Read the complete file
    All {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read the data
    Data {
        /// Path to Pithos file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Path in Pithos file
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Specific byte ranges in the file
        #[arg(short, long, value_parser=parse_range_input, value_delimiter=',', value_name = "START:END,...")]
        ranges: Option<Vec<Range<u64>>>,
    },
    /// Read the Table of Contents
    Directory {
        /// Input file
        ///
        ///ToDo: Filter to display only specific entries of the ToC?
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
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
}

#[derive(Subcommand)]
enum ModifyCommands {
    /// Add a reader to the encryption metadata
    AddReader {
        // Readers public key for shared key generation
        #[arg(long)]
        reader_public_key: Option<String>,
    },
    /// Set all readers in the encryption metadata
    SetReaders {
        // List of public keys for encryption packe generation
        #[arg(long)]
        reader_public_keys: Option<Vec<String>>,
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

    // Evaluate provided log level
    let log_level = evaluate_log_level(cli.log_level);

    // Initialize logger
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .compact()
            .with_max_level(log_level)
            .with_file(true)
            .with_line_number(true)
            .with_target(false)
            .finish(),
    )?;

    // Evaluate subcommand
    match cli.command {
        PithosCommands::Read { read_command } => match read_command {
            ReadCommands::Info { file, path } => {
                let key = load_private_key_from_pem(
                    &cli.secret_keys
                        .clone()
                        .expect("Private key expected to read directory"),
                )?;
                let mut reader = PithosReaderSimple::new_with_key(&file, key)?;
                let (directory, _) = reader.read_directory()?;

                println!("\nAvailable files in {file:?}:\n{}", "-".repeat(50));
                directory
                    .files
                    .iter()
                    .for_each(|f| println!("  - {:?} | {}", f.file_type, f.path))
            }
            ReadCommands::All { .. } => {
                unimplemented!("Extraction of all files not yet implemented")
            }
            ReadCommands::Data { file, path, ranges } => {
                let key = load_private_key_from_pem(
                    &cli.secret_keys
                        .clone()
                        .expect("Private key expected to read directory"),
                )?;

                let mut reader = PithosReaderSimple::new_with_key(&file, key)?;
                let (directory, _) = reader.read_directory()?;

                reader.read_file(
                    path.to_str()
                        .expect("No inner path provided or path contains invalid UTF-8"),
                    &directory,
                    cli.output.as_ref(),
                    ranges,
                )?;
            }
            ReadCommands::Directory { file } => {
                let key = load_private_key_from_pem(
                    &cli.secret_keys
                        .clone()
                        .expect("Private key expected to read directory"),
                )?;
                let mut reader = PithosReaderSimple::new_with_key(&file, key)?;
                println!("{:#?}", reader.read_directory()?);
            }
            ReadCommands::Search { .. } => {}
        },
        PithosCommands::Create { cdc, files } => {
            if files.is_empty() {
                return Err(PithosCliError::InvalidArgumentError(
                    "No files provided".to_string(),
                ));
            }

            let output = if let Some(outfile) = cli.output {
                std::fs::File::create(outfile).map_err(PithosError::Io)?
            } else {
                // Default outfile
                println!("No outfile specified, writing output to \"/tmp/out.pithos\""); //TODO: Replace with tracing::warn!()
                std::fs::File::create("/tmp/out.pithos").map_err(PithosError::Io)?
            };

            let sender_key = load_private_key_from_pem(
                &cli.secret_keys
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

            writer
                .write_file_header()
                .map_err(PithosError::Serialization)?;
            writer.process_input_files(input_files?)?;
            writer.write_directory()?;
        }
        PithosCommands::CreateKeypair { .. } => {
            let private_key = generate_private_key().map_err(PithosError::Crypt)?;
            let public_key = PublicKey::from(&private_key);

            // Write output
            let mut output_target: Box<dyn Write> = if let Some(dest) = cli.output {
                Box::new(std::fs::File::create(dest).map_err(PithosError::Io)?)
            } else {
                Box::new(std::io::stdout())
            };
            output_target
                .write_all(&private_key_to_pem_bytes(&private_key).map_err(PithosError::Crypt)?)
                .map_err(PithosError::Io)?;
            output_target
                .write_all(&public_key_to_pem_bytes(&public_key).map_err(PithosError::Crypt)?)
                .map_err(PithosError::Io)?;
        }
        PithosCommands::Modify { .. } => {
            unimplemented!()
        }
        PithosCommands::Export { format } => {
            if let Some(format) = format {}
            unimplemented!("Export to different formats is not yet implemented")
        }
    }

    Ok(())
}
