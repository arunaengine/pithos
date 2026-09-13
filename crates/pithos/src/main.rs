mod io;
pub mod utils;

use crate::io::utils::{load_private_key_from_pem, load_public_key_from_pem};
use clap::{Parser, Subcommand, ValueEnum};
use pithos_lib::adapters::crypt4gh;
use pithos_lib::adapters::crypt4gh::Crypt4GHError;
use pithos_lib::archive::{
    AccessKeys, AppendDurability, AppendOptions, Archive, ArchiveWriter, CdcConfig, OpenOptions,
    ProcessingOptions, WriteOptions, WriterError,
};
use pithos_lib::crypto::{PrivateKey, PublicKey, generate_private_key};
use pithos_lib::error::PithosError;
use pithos_lib::fs::ingest::build_input_manifest;
use pithos_lib::fs::{FsError, append_files, extract_all, grant_readers};
use pithos_lib::source::FileSource;
use rustix::fs::{AtFlags, Mode, OFlags, fchmod, linkat, open, openat, unlinkat};
use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::TryInitError;
use utils::conversion::{evaluate_log_level, parse_cdc_input, parse_range_input};

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

#[derive(Clone, Copy, Default, ValueEnum)]
enum CliAppendDurability {
    #[default]
    Flush,
    SyncAll,
}

impl From<CliAppendDurability> for AppendDurability {
    fn from(value: CliAppendDurability) -> Self {
        match value {
            CliAppendDurability::Flush => Self::Flush,
            CliAppendDurability::SyncAll => Self::SyncAll,
        }
    }
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
        cdc: Option<CdcConfig>,
        /// Create a local, uncompressed, unencrypted base archive
        #[arg(long, conflicts_with_all = ["secret_key", "public_keys"])]
        plain: bool,
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
        #[arg(short = 'k', long)]
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
        /// Durability after publishing the appended directory
        #[arg(long, value_enum, default_value_t)]
        durability: CliAppendDurability,
        /// Path to Pithos file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Add files to an existing Pithos container
    Files {
        /// Path to Pithos file
        #[arg(short, long, value_name = "PITHOS FILE")]
        file: PathBuf,
        /// Set values for content-defined chunking
        #[arg(long = "cdc", value_parser = parse_cdc_input, value_name = "MIN,AVG,MAX")]
        cdc: Option<CdcConfig>,
        /// Durability after publishing the appended directory
        #[arg(long, value_enum, default_value_t)]
        durability: CliAppendDurability,
        /// Input files
        #[arg(value_name = "FILES")]
        files: Vec<PathBuf>,
    },
}

#[derive(Error, Debug)]
pub enum PithosCliError {
    #[error("tracing initialization error: {0}")]
    TracingError(#[from] TryInitError),
    #[error("Invalid argument: {0}")]
    InvalidArgumentError(String),
    #[error("Pithos Error: {0}")]
    PithosError(#[from] PithosError),
    #[error("Filesystem Error: {0}")]
    FilesystemError(#[from] FsError),
    #[error("Writer Error: {0}")]
    WriterError(#[from] WriterError),
    #[error("Crypt4GH error: {0}")]
    Crypt4GHError(#[from] Crypt4GHError),
    #[error("{operation} failed for {path}: {source}")]
    KeyFile {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{operation} failed for {path}: {source}")]
    KeyParse {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: pithos_lib::crypto::CryptoError,
    },
    #[error("{operation} failed for {path}: {source}")]
    OutputFile {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[tracing::instrument(level = "trace", skip())]
fn run() -> Result<(), PithosCliError> {
    // Parse CLI parameter input
    let cli = Cli::parse();

    // Initialize tracing logger
    let logging_filter = evaluate_log_level(cli.log_level)?;
    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_file(cli.verbose)
        .with_line_number(cli.verbose)
        .with_target(cli.verbose)
        .with_filter(logging_filter);

    tracing_subscriber::registry().with(fmt_layer).try_init()?;

    // Evaluate subcommand
    match cli.command {
        PithosCommands::Read { read_command } => match read_command {
            ReadCommands::Info { file, path } => {
                let path_str = path.to_str().ok_or_else(|| {
                    PithosCliError::InvalidArgumentError("archive path is not valid UTF-8".into())
                })?;
                let archive = open_archive(&file, optional_private_key(&cli.secret_key)?)?;
                match archive.entry(path_str)? {
                    Some(entry) => write_stdout(format_args!("{entry:#?}"))?,
                    None => Err(PithosError::FileNotFound(path_str.to_string()))?,
                }
            }
            ReadCommands::List { file } => {
                let archive = open_archive(&file, optional_private_key(&cli.secret_key)?)?;
                for entry in archive.entries() {
                    write_stdout(format_args!("{} {:?} {}", entry.id, entry.kind, entry.path))?;
                }
            }
            ReadCommands::All { file } => {
                let archive = open_archive(&file, optional_private_key(&cli.secret_key)?)?;
                let output = cli
                    .output
                    .as_deref()
                    .unwrap_or_else(|| std::path::Path::new("."));
                extract_all(&archive, output)?;
            }
            ReadCommands::Data {
                file,
                paths,
                ranges,
            } => {
                if paths.is_empty() {
                    return Err(PithosCliError::InvalidArgumentError(
                        "at least one archive path is required".into(),
                    ));
                }
                if cli.output.is_some() && paths.len() > 1 {
                    return Err(PithosCliError::InvalidArgumentError(
                        "a file output accepts exactly one archive path".into(),
                    ));
                }
                let archive = open_archive(&file, optional_private_key(&cli.secret_key)?)?;
                if let Some(output_path) = cli.output.as_ref() {
                    if let Some(path) = paths.first() {
                        let path = path.to_str().ok_or_else(|| {
                            PithosCliError::InvalidArgumentError(
                                "archive path is not valid UTF-8".into(),
                            )
                        })?;
                        let mut output = StagedOutput::create(
                            output_path,
                            Mode::RUSR
                                | Mode::WUSR
                                | Mode::RGRP
                                | Mode::WGRP
                                | Mode::ROTH
                                | Mode::WOTH,
                            "open archive output",
                        )?;
                        let result = (|| {
                            if let Some(ranges) = &ranges {
                                for range in ranges {
                                    archive.copy_range_to(
                                        path,
                                        range.clone(),
                                        output.file_mut(),
                                    )?;
                                }
                            } else {
                                archive.copy_to(path, output.file_mut())?;
                            }
                            output.flush("flush archive output")
                        })();
                        result?;
                        output.publish("publish archive output")?;
                    }
                } else {
                    for path in paths {
                        let path = path.to_str().ok_or_else(|| {
                            PithosCliError::InvalidArgumentError(
                                "archive path is not valid UTF-8".into(),
                            )
                        })?;
                        wait_before_stdout_for_test();
                        let mut output = std::io::stdout();
                        if let Some(ranges) = &ranges {
                            for range in ranges {
                                archive.copy_range_to(path, range.clone(), &mut output)?;
                            }
                        } else {
                            archive.copy_to(path, &mut output)?;
                        }
                        output.flush().map_err(PithosError::Io)?;
                    }
                }
            }
            ReadCommands::Directory { file } => {
                let archive = open_archive(&file, optional_private_key(&cli.secret_key)?)?;
                for entry in archive.entries() {
                    write_stdout(format_args!("{entry:#?}"))?;
                }
            }
        },
        PithosCommands::Create { cdc, plain, files } => {
            if plain && (cli.secret_key.is_some() || cli.public_keys.is_some()) {
                return Err(PithosCliError::InvalidArgumentError(
                    "--plain conflicts with --secret-key and --public-keys".into(),
                ));
            }
            if files.is_empty() {
                return Err(PithosCliError::InvalidArgumentError(
                    "No files provided".to_string(),
                ));
            }

            let (options, processing) = if plain {
                (
                    WriteOptions::base().with_cdc(cdc.unwrap_or_default()),
                    ProcessingOptions::new(false, 0).expect("zero compression is valid"),
                )
            } else {
                let sender_key = required_private_key(&cli.secret_key)?;
                let reader_keys: Result<Vec<PublicKey>, PithosCliError> = cli
                    .public_keys
                    .ok_or_else(|| {
                        PithosCliError::InvalidArgumentError(
                            "at least one recipient key is required".into(),
                        )
                    })?
                    .iter()
                    .map(|path| load_public_key_from_pem(path))
                    .collect();
                (
                    WriteOptions::new(sender_key, reader_keys?).with_cdc(cdc.unwrap_or_default()),
                    ProcessingOptions::default(),
                )
            };
            options.validate()?;
            let manifest = build_input_manifest(&files)?;

            let output_path = match cli.output {
                Some(path) => path,
                None => {
                    write_stdout(format_args!(
                        "No outfile specified, writing output to \"/tmp/out.pithos\""
                    ))?;
                    PathBuf::from("/tmp/out.pithos")
                }
            };
            let mut output = StagedOutput::create(
                &output_path,
                Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                "open archive output",
            )?;
            let mut writer = match ArchiveWriter::create(output.take_file(), options) {
                Ok(writer) => writer,
                Err(error) => {
                    let (error, sink) = error.into_parts();
                    drop(sink);
                    return Err(PithosCliError::PithosError(error));
                }
            };

            tracing::info!("Start creating Pithos file");
            if let Err(error) = fail_after_create_for_test() {
                discard_incomplete_writer(writer);
                return Err(error.into());
            }
            if let Err(error) = manifest.ingest(&mut writer, processing) {
                discard_incomplete_writer(writer);
                return Err(error.into());
            }
            match writer.finish() {
                Ok(sink) => {
                    output.restore_file(sink);
                    output.publish("publish archive output")?;
                }
                Err(error) => {
                    let (error, sink) = error.into_parts();
                    drop(sink);
                    return Err(PithosCliError::PithosError(error));
                }
            }
        }
        PithosCommands::Keypair { prefix, .. } => {
            let prefix = validate_keypair_prefix(prefix)?;
            let private_key = generate_private_key();
            let public_key = private_key.public_key();
            let private_pem = private_key
                .to_private_pem_bytes()
                .map_err(PithosError::Crypt)?;
            let public_pem = public_key
                .to_public_pem_bytes()
                .map_err(PithosError::Crypt)?;

            if let Some(output) = cli.output {
                if let Some(directory) = open_keypair_output_directory(&output)? {
                    write_keypair_files(&output, directory, &prefix, &private_pem, &public_pem)?;
                } else {
                    write_combined_keypair_file(&output, &private_pem, &public_pem)?;
                }
            } else {
                wait_before_stdout_for_test();
                let mut output = std::io::stdout();
                output.write_all(&private_pem).map_err(PithosError::Io)?;
                output.write_all(&public_pem).map_err(PithosError::Io)?;
                output.flush().map_err(PithosError::Io)?;
            }
        }
        PithosCommands::Append { command } => match command {
            AppendCommands::Readers {
                file,
                ids,
                durability,
            } => {
                let ids = ids.unwrap_or_default();
                if ids.is_empty() {
                    return Err(PithosCliError::InvalidArgumentError(
                        "No available id or path provided".to_string(),
                    ));
                }
                let sender_key = required_private_key(&cli.secret_key)?;
                let reader_keys = required_recipient_keys(&cli.public_keys)?;
                grant_readers(
                    &file,
                    AppendOptions::new(sender_key, reader_keys).with_durability(durability.into()),
                    &ids,
                )?;
            }
            AppendCommands::Files {
                file,
                cdc,
                durability,
                files,
            } => {
                if files.is_empty() {
                    return Err(PithosCliError::InvalidArgumentError(
                        "No files provided".to_string(),
                    ));
                }
                let sender_key = required_private_key(&cli.secret_key)?;
                let reader_keys = required_recipient_keys(&cli.public_keys)?;
                append_files(
                    &file,
                    AppendOptions::new(sender_key, reader_keys)
                        .with_cdc(cdc.unwrap_or_default())
                        .with_durability(durability.into()),
                    &files,
                )?;
            }
        },
        PithosCommands::Export { file, path, .. } => {
            let path_str = path.to_str().ok_or_else(|| {
                PithosCliError::InvalidArgumentError("archive path is not valid UTF-8".into())
            })?;
            let sender_key = required_private_key(&cli.secret_key)?;
            let reader_keys: Result<Vec<PublicKey>, PithosCliError> = cli
                .public_keys
                .ok_or_else(|| {
                    PithosCliError::InvalidArgumentError(
                        "at least one recipient key is required".into(),
                    )
                })?
                .iter()
                .map(|path| load_public_key_from_pem(path))
                .collect();

            let archive = open_archive(&file, Some(sender_key))?;

            if let Some(destination) = cli.output {
                let mut output = StagedOutput::create(
                    &destination,
                    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                    "open export output",
                )?;
                let result = (|| {
                    crypt4gh::export(&archive, path_str, reader_keys?, output.file_mut())?;
                    output.flush("flush export output")
                })();
                result?;
                output.publish("publish export output")?;
            } else {
                wait_before_stdout_for_test();
                let mut output = std::io::stdout();
                crypt4gh::export(&archive, path_str, reader_keys?, &mut output)?;
                output.flush().map_err(PithosError::Io)?;
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn required_private_key(path: &Option<PathBuf>) -> Result<PrivateKey, PithosCliError> {
    let path = path
        .as_ref()
        .ok_or_else(|| PithosCliError::InvalidArgumentError("private key is required".into()))?;
    load_private_key_from_pem(path)
}

fn optional_private_key(path: &Option<PathBuf>) -> Result<Option<PrivateKey>, PithosCliError> {
    path.as_ref()
        .map(|path| load_private_key_from_pem(path))
        .transpose()
}

fn validate_keypair_prefix(prefix: Option<String>) -> Result<String, PithosCliError> {
    let prefix = prefix.unwrap_or_else(|| "pithos_key".to_string());
    let mut components = Path::new(&prefix).components();
    let is_one_normal_component = matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    );
    if prefix.is_empty()
        || prefix.contains(['/', '\\'])
        || Path::new(&prefix).is_absolute()
        || !is_one_normal_component
    {
        return Err(PithosCliError::InvalidArgumentError(
            "key prefix must be one normal filename component".into(),
        ));
    }
    Ok(prefix)
}

fn open_output_directory(path: &Path) -> rustix::io::Result<File> {
    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = File::from(open(
        start,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);

    for component in path.components() {
        if matches!(component, Component::RootDir | Component::CurDir) {
            continue;
        }
        directory = File::from(openat(
            &directory,
            component.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
    }
    Ok(directory)
}

fn open_keypair_output_directory(path: &Path) -> Result<Option<File>, PithosCliError> {
    match open_output_directory(path) {
        Ok(directory) => Ok(Some(directory)),
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {
            Ok(None)
        }
        Err(source) => Err(PithosCliError::OutputFile {
            operation: "inspect keypair output",
            path: path.to_path_buf(),
            source: source.into(),
        }),
    }
}

fn write_combined_keypair_file(
    path: &Path,
    private_pem: &[u8],
    public_pem: &[u8],
) -> Result<(), PithosCliError> {
    let mut output = StagedOutput::create(
        path,
        Mode::RUSR | Mode::WUSR,
        "open combined keypair output",
    )?;
    fchmod(output.file_mut(), Mode::RUSR | Mode::WUSR).map_err(|source| {
        PithosCliError::OutputFile {
            operation: "set combined keypair permissions",
            path: path.to_path_buf(),
            source: source.into(),
        }
    })?;
    let result =
        (|| {
            output.file_mut().write_all(private_pem).map_err(|source| {
                PithosCliError::OutputFile {
                    operation: "write private key",
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            output.file_mut().write_all(public_pem).map_err(|source| {
                PithosCliError::OutputFile {
                    operation: "write public key",
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            output.flush("flush combined keypair output")
        })();
    result?;
    output.publish("publish combined keypair output")
}

fn write_keypair_files(
    output_directory: &Path,
    directory: File,
    prefix: &str,
    private_pem: &[u8],
    public_pem: &[u8],
) -> Result<(), PithosCliError> {
    let private_name = format!("{prefix}.sec.pem");
    let public_name = format!("{prefix}.pub.pem");
    let private_path = output_directory.join(&private_name);
    let public_path = output_directory.join(&public_name);

    let mut private_output = create_keypair_file(
        &directory,
        &private_name,
        &private_path,
        Mode::RUSR | Mode::WUSR,
        true,
    )?;
    let mut public_output = match create_keypair_file(
        &directory,
        &public_name,
        &public_path,
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        false,
    ) {
        Ok(file) => file,
        Err(error) => {
            drop(private_output);
            remove_keypair_file(&directory, &private_name);
            return Err(error);
        }
    };

    let result = (|| {
        private_output
            .write_all(private_pem)
            .map_err(|source| PithosCliError::OutputFile {
                operation: "write private key",
                path: private_path.clone(),
                source,
            })?;
        public_output
            .write_all(public_pem)
            .map_err(|source| PithosCliError::OutputFile {
                operation: "write public key",
                path: public_path.clone(),
                source,
            })?;
        private_output
            .flush()
            .map_err(|source| PithosCliError::OutputFile {
                operation: "flush private key",
                path: private_path.clone(),
                source,
            })?;
        public_output
            .flush()
            .map_err(|source| PithosCliError::OutputFile {
                operation: "flush public key",
                path: public_path.clone(),
                source,
            })
    })();
    if result.is_err() {
        drop(private_output);
        drop(public_output);
        remove_keypair_file(&directory, &private_name);
        remove_keypair_file(&directory, &public_name);
    }
    result
}

fn create_keypair_file(
    directory: &File,
    name: &str,
    path: &Path,
    mode: Mode,
    private: bool,
) -> Result<File, PithosCliError> {
    let fd = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
    )
    .map_err(|source| PithosCliError::OutputFile {
        operation: if private {
            "create private key"
        } else {
            "create public key"
        },
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    if private && let Err(source) = fchmod(&fd, Mode::RUSR | Mode::WUSR) {
        drop(fd);
        remove_keypair_file(directory, name);
        return Err(PithosCliError::OutputFile {
            operation: "set private key permissions",
            path: path.to_path_buf(),
            source: source.into(),
        });
    }
    Ok(File::from(fd))
}

fn remove_keypair_file(directory: &File, name: &str) {
    let _ = unlinkat(directory, name, AtFlags::empty());
}

struct StagedOutput {
    directory: File,
    destination_name: OsString,
    path: PathBuf,
    file: Option<File>,
}

impl StagedOutput {
    fn create(path: &Path, mode: Mode, operation: &'static str) -> Result<Self, PithosCliError> {
        let destination_name =
            path.file_name()
                .map(OsString::from)
                .ok_or_else(|| PithosCliError::OutputFile {
                    operation,
                    path: path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "output path must name a file",
                    ),
                })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory =
            open_output_directory(parent).map_err(|source| PithosCliError::OutputFile {
                operation,
                path: path.to_path_buf(),
                source: source.into(),
            })?;
        let file = File::from(
            openat(
                &directory,
                ".",
                OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
                mode,
            )
            .map_err(|source| PithosCliError::OutputFile {
                operation,
                path: path.to_path_buf(),
                source: source.into(),
            })?,
        );

        Ok(Self {
            directory,
            destination_name,
            path: path.to_path_buf(),
            file: Some(file),
        })
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("staged output file is present")
    }

    fn take_file(&mut self) -> File {
        self.file.take().expect("staged output file is present")
    }

    fn restore_file(&mut self, file: File) {
        self.file = Some(file);
    }

    fn flush(&mut self, operation: &'static str) -> Result<(), PithosCliError> {
        self.file_mut()
            .flush()
            .map_err(|source| PithosCliError::OutputFile {
                operation,
                path: self.path.clone(),
                source,
            })
    }

    fn publish(mut self, operation: &'static str) -> Result<(), PithosCliError> {
        let file = self.take_file();
        linkat(
            &file,
            "",
            &self.directory,
            &self.destination_name,
            AtFlags::EMPTY_PATH,
        )
        .map_err(|source| PithosCliError::OutputFile {
            operation,
            path: self.path.clone(),
            source: source.into(),
        })
    }
}

fn required_recipient_keys(paths: &Option<Vec<PathBuf>>) -> Result<Vec<PublicKey>, PithosCliError> {
    let paths = paths.as_ref().ok_or_else(|| {
        PithosCliError::InvalidArgumentError("at least one recipient key is required".into())
    })?;
    if paths.is_empty() {
        return Err(PithosCliError::InvalidArgumentError(
            "at least one recipient key is required".into(),
        ));
    }
    paths
        .iter()
        .map(|path| load_public_key_from_pem(path))
        .collect()
}

fn write_stdout(arguments: std::fmt::Arguments<'_>) -> Result<(), PithosCliError> {
    wait_before_stdout_for_test();
    let mut output = std::io::stdout().lock();
    writeln!(output, "{arguments}").map_err(PithosError::Io)?;
    Ok(())
}

fn wait_before_stdout_for_test() {
    #[cfg(debug_assertions)]
    if std::env::var_os("PITHOS_TEST_DELAY_STDOUT").is_some() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn discard_incomplete_writer(writer: ArchiveWriter<File>) {
    match writer.into_incomplete() {
        Ok(sink) => drop(sink),
        Err(writer) => drop(writer),
    }
}

// This deliberately narrow process-test seam exercises cleanup after the
// destination has been created without depending on a filesystem race.
fn fail_after_create_for_test() -> Result<(), PithosError> {
    #[cfg(debug_assertions)]
    {
        if std::env::var_os("PITHOS_TEST_FAIL_AFTER_CREATE").is_some() {
            return Err(PithosError::Io(std::io::Error::other(
                "writer runtime failure injected for testing",
            )));
        }
    }
    Ok(())
}

fn open_archive(
    path: &std::path::Path,
    key: Option<PrivateKey>,
) -> Result<Archive<FileSource>, PithosError> {
    let access_keys = key.map_or_else(AccessKeys::new, |key| AccessKeys::new().with_key(key));
    Archive::open(
        FileSource::open(path)?,
        OpenOptions::default().with_access_keys(access_keys),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_commands_parse_without_constructing_a_legacy_reader() {
        assert!(Cli::try_parse_from(["pithos", "read", "list", "archive.pith"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "pithos",
                "read",
                "data",
                "archive.pith",
                "entry",
                "--ranges",
                "4:2",
            ])
            .is_err()
        );
    }

    #[test]
    fn reader_key_requirement_is_a_cli_error() {
        assert!(matches!(
            required_private_key(&None),
            Err(PithosCliError::InvalidArgumentError(_))
        ));
    }
}
