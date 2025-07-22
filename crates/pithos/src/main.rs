mod io;
pub mod utils;

use crate::io::utils::load_key_from_pem;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use utils::conversion::evaluate_log_level;

#[derive(Clone, ValueEnum)]
enum KeyFormat {
    Openssl,
    Crypt4gh,
    Raw,
}

#[derive(Clone, ValueEnum)]
enum ExportFormat {
    Pithos,
    Crypt4gh,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Optionally set the log level
    #[arg(long, value_name = "LOG_LEVEL")]
    log_level: Option<String>,

    /// Optionally set the log file
    log_file: Option<PathBuf>,

    /// Private key for encryption/decryption
    #[arg(long)]
    private_key: Option<PathBuf>, // File path; if None -> Default file: ~/.pithos/sec_key.pem

    /// Output destination; Default is stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Subcommands
    #[command(subcommand)]
    command: PithosCommands,
}

#[derive(Subcommand)]
enum PithosCommands {
    /// Create a Pithos file from some input
    Create {
        /// Expect file metadata in JSON format under 'file-path.meta'
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
        /// Key format; Default is openSSL x25519 pem
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
    /// Read the technical metadata of the file
    Info {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read the complete file
    All {
        /// Input file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Read the data
    Data {
        /// Input file
        ///
        ///ToDo: Filter to display only specific entries of the ToC?
        #[arg(value_name = "FILE")]
        file: PathBuf,
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
        /// Output destination; Default is stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fuzzy search or exact
        #[arg(short, long)]
        fuzzy_search: bool,

        /// Input file
        ///
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

#[tracing::instrument(level = "trace", skip())]
#[tokio::main]
async fn main() -> Result<()> {
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

    // Load private key if provided
    let private_key = if let Some(key_path) = cli.private_key {
        Some(load_key_from_pem(&key_path, true)?)
    } else if let Ok(key_bytes) =
        load_key_from_pem(&PathBuf::from("~/.pithos/private_key.pem"), true)
    {
        Some(key_bytes)
    } else {
        None
    };

    // Evaluate subcommand
    match cli.command {
        PithosCommands::Read { read_command } => match read_command {
            ReadCommands::Info { file } => {}
            ReadCommands::All { .. } => {}
            ReadCommands::Data { file } => {}
            ReadCommands::Directory { file } => {}
            ReadCommands::Search { .. } => {}
        },
        PithosCommands::Create {
            metadata: _,
            range_files: _,
            auto_generate_ranges: _,
            ranges_regex: _,
            files,
            reader_public_keys,
        } => {}
        PithosCommands::CreateKeypair { format } => {
            // x25519 openSSL keypair
            // x25519 Crypt4GH keypair
            // Output format parameter?
            //  - Raw
            //  - Pem
            //  - ?

            // Evaluate output format
            let format = format.as_ref().unwrap_or(&KeyFormat::Openssl);

            // Generate keypair
            let (seckey_bytes, pubkey_bytes) = match format {
                KeyFormat::Openssl => {
                    let openssl_keypair = openssl::pkey::PKey::generate_x25519()?;
                    (
                        openssl_keypair.private_key_to_pem_pkcs8()?,
                        openssl_keypair.public_key_to_pem()?,
                    )
                }
                KeyFormat::Crypt4gh => {
                    unimplemented!("Crypt4GH key generation not yet implemented")
                }
                KeyFormat::Raw => {
                    let openssl_keypair = openssl::pkey::PKey::generate_x25519()?;
                    (
                        openssl_keypair.raw_private_key()?,
                        openssl_keypair.raw_public_key()?,
                    )
                }
            };

            // Write output
            if let Some(dest) = cli.output {
                let mut output_target = File::create(dest).await?;
                output_target.write_all(&seckey_bytes).await?;
                output_target.write_all(&pubkey_bytes).await?;
            } else {
                let mut output_target = tokio::io::stdout();
                output_target.write_all(&seckey_bytes).await?;
                output_target.write_all(&pubkey_bytes).await?;
            }
        }
        PithosCommands::Modify { .. } => {}
        PithosCommands::Export { .. } => {}
    }

    // Continued program logic goes here...
    Ok(())
}
