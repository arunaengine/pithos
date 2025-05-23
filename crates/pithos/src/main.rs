mod io;
mod structs;
pub mod utils;

use crate::io::utils::load_key_from_pem;
use anyhow::{anyhow, Result};
use async_channel::TryRecvError;
use clap::{Parser, Subcommand, ValueEnum};
use futures_util::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressState, ProgressStyle};
use pithos_lib::helpers::footer_parser::{Footer, FooterParser, FooterParserState};
use pithos_lib::helpers::notifications::{DirOrFileIdx, Message};
use pithos_lib::helpers::structs::FileContext;
use pithos_lib::pithos::pithosreader::PithosReader;
use pithos_lib::pithos::pithoswriter::PithosWriter;
use pithos_lib::pithos::structs::{
    DirContextVariants, EndOfFileMetadata, FileContextVariants, EOF_META_LEN,
};
use rand::distr::Alphanumeric;
use rand::Rng;
use std::fmt::Write;
use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::{pin, task};
use tokio_util::io::ReaderStream;
use tracing::trace;
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
    ContentList {
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
            ReadCommands::Info { file } => {
                // Open file
                let mut input_file = File::open(file).await?;

                // Read EndOfFileMetadata bytes
                input_file
                    .seek(SeekFrom::Start(
                        input_file.metadata().await?.len() - EOF_META_LEN as u64,
                    ))
                    .await?;
                let mut buf = [0; EOF_META_LEN];
                input_file.read_exact(&mut buf).await?;

                // Try to parse EndOfFileMetadata
                let eof_meta: EndOfFileMetadata = borsh::from_slice(&buf)?;

                println!("{eof_meta}");

                //ToDo: OutputWriter
            }
            ReadCommands::All { .. } => {

                //ToDo: Ranges & Metadata individual files
            }
            ReadCommands::Data { file } => {
                // Parse Footer
                let mut input_file = File::open(file.clone()).await?;
                let file_meta = input_file.metadata().await?;

                let footer_prediction = if file_meta.len() < 65536 * 2 {
                    file_meta.len() // 131072 always fits in i64 ...
                } else {
                    65536 * 2
                };

                // Read footer bytes in FooterParser
                input_file
                    .seek(SeekFrom::End(-(footer_prediction as i64)))
                    .await?;
                let buf = &mut vec![0; footer_prediction as usize]; // Has to be vec as length is defined by dynamic value
                input_file.read_exact(buf).await?;

                let mut parser = FooterParser::new(buf)?;
                if let Some(p_key) = private_key.as_ref() {
                    parser = parser.add_recipient(p_key)
                };
                parser = parser.parse()?;

                // Check if bytes are missing
                let mut missing_buf;
                if let FooterParserState::Missing(missing_bytes) = parser.state {
                    let needed_bytes = footer_prediction + missing_bytes as u64;
                    input_file
                        .seek(SeekFrom::End(-(needed_bytes as i64)))
                        .await?;
                    missing_buf = vec![0; missing_bytes as usize]; // Has to be vec as length is defined by dynamic value
                    input_file.read_exact(&mut missing_buf).await?;

                    parser = parser.add_bytes(&missing_buf)?;
                    parser = parser.parse()?
                }

                // Parse the footer bytes and display Table of Contents
                let footer: Footer = parser.try_into()?;

                // Output target ... ?
                let base_path = Arc::new(PathBuf::from(
                    cli.output
                        .ok_or_else(|| anyhow!("No output target provided"))?,
                ));

                // Create directory structure
                for dir in footer.table_of_contents.directories {
                    if let DirContextVariants::DirDecrypted(dir_ctx) = dir {
                        //ToDo: Sanitize file path
                        tokio::fs::create_dir(base_path.clone().join(dir_ctx.file_path)).await?;
                    }
                }

                // Create PithosReader for each file
                let sem = Arc::new(Semaphore::new(16));
                let mut process_handles = Vec::with_capacity(footer.table_of_contents.files.len());

                let keys = footer
                    .encryption_keys
                    .map(|keys| {
                        keys.keys
                            .iter()
                            .filter_map(|(k, idx)| {
                                if let DirOrFileIdx::File(i) = idx {
                                    Some((k.clone(), *i))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let m = Arc::new(MultiProgress::new());
                let style = ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    ?
                    .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
                    .progress_chars("#>-");

                for (idx, file_ctx_variant) in
                    footer.table_of_contents.files.into_iter().enumerate()
                {
                    let permit = Arc::clone(&sem).acquire_owned().await;
                    let base_path_clone = Arc::clone(&base_path);
                    let file_clone = file.clone();
                    let key_clone = keys.clone();
                    let style = style.clone();
                    let m = m.clone();
                    if let FileContextVariants::FileDecrypted(file_ctx) = file_ctx_variant {
                        process_handles.push(task::spawn(async move {
                            let _permit = permit;
                            trace!(base = ?base_path_clone);

                            let file_path = base_path_clone
                                .join(file_ctx.file_path.to_string().trim_start_matches('/'));

                            trace!(file_path = ?file_path, "Processing file");
                            let file_handle = File::create(&file_path).await?;

                            // Open pithos file handle and read file range
                            let mut pithos_file = File::open(file_clone).await?;
                            pithos_file
                                .seek(SeekFrom::Start(file_ctx.file_start))
                                .await?;

                            let disk_size: usize =
                                (file_ctx.file_end - file_ctx.file_start).try_into()?;

                            let pb = m.add(ProgressBar::new(disk_size as u64));
                            pb.set_style(style);

                            // Send at least file_ctx.compressed_size bytes pithos_file
                            let (data_sender, data_receiver) = async_channel::bounded(3);
                            tokio::spawn(async move {
                                let mut remaining = disk_size;
                                let mut input_stream = ReaderStream::new(pithos_file);
                                while let Some(bytes) = input_stream.next().await {
                                    let mut bytes = bytes?;
                                    pb.inc(bytes.len() as u64);
                                    if bytes.len() < remaining {
                                        remaining = remaining.saturating_sub(bytes.len());
                                        data_sender.send(Ok(bytes)).await?;
                                    } else {
                                        data_sender
                                            .send(Ok(bytes.split_to(remaining as usize)))
                                            .await?;
                                        break;
                                    }
                                }
                                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                            });

                            // Generate FileContext without encryption keys
                            let ctx = file_ctx.try_into_file_context(idx)?;

                            pin!(data_receiver);
                            let mut reader = PithosReader::new_with_writer(
                                data_receiver,
                                file_handle,
                                ctx,
                                key_clone,
                                None,
                            )
                            .await?;
                            reader.process_bytes().await?;

                            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                        }));
                    }
                }

                // Await all readers
                futures::future::join_all(process_handles)
                    .await
                    .into_iter()
                    .for_each(|e| e.unwrap().unwrap());
            }
            ReadCommands::ContentList { file } => {
                // Parse Footer
                let mut input_file = File::open(file.clone()).await?;
                let file_meta = input_file.metadata().await?;

                let footer_prediction = if file_meta.len() < 65536 * 2 {
                    file_meta.len() // 131072 always fits in i64 ...
                } else {
                    65536 * 2
                };

                // Read footer bytes in FooterParser
                input_file
                    .seek(SeekFrom::End(-(footer_prediction as i64)))
                    .await?;
                let buf = &mut vec![0; footer_prediction as usize]; // Has to be vec as length is defined by dynamic value
                input_file.read_exact(buf).await?;

                let mut parser = FooterParser::new(buf)?;
                if let Some(p_key) = private_key.as_ref() {
                    parser = parser.add_recipient(p_key)
                };
                parser = parser.parse()?;

                // Check if bytes are missing
                let mut missing_buf;
                if let FooterParserState::Missing(missing_bytes) = parser.state {
                    let needed_bytes = footer_prediction + missing_bytes as u64;
                    input_file
                        .seek(SeekFrom::End(-(needed_bytes as i64)))
                        .await?;
                    missing_buf = vec![0; missing_bytes as usize]; // Has to be vec as length is defined by dynamic value
                    input_file.read_exact(&mut missing_buf).await?;

                    parser = parser.add_bytes(&missing_buf)?;
                    parser = parser.parse()?
                }

                // Parse the footer bytes and display Table of Contents
                let footer: Footer = parser.try_into()?;
                println!("{:#?}", footer.table_of_contents);

                //TODO: Output writer
            }
            ReadCommands::Search { .. } => {}
        },
        PithosCommands::Create {
            metadata: _,
            range_files: _,
            auto_generate_ranges: _,
            ranges_regex: _,
            files,
            reader_public_keys,
        } => {
            // Generate random symmetric "key" for encryption
            let key: [u8; 32] = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect::<String>()
                .to_ascii_lowercase()
                .as_bytes()
                .try_into()?;

            // Load public keys from pem files
            let recipient_keys: Result<Vec<_>> = reader_public_keys
                .unwrap_or_default()
                .iter()
                .map(|pk| load_key_from_pem(pk, false))
                .collect();
            let recipient_keys = recipient_keys?;

            // Create file context and data stream
            let (ctx_sender, ctx_receiver) = async_channel::unbounded(); // Channel cap?
            let (stream_sender, stream_receiver) = async_channel::bounded(10); // Channel cap?

            let pb = Arc::new(ProgressBar::new(
                files
                    .iter()
                    .map(|f| f.metadata().map(|m| m.size()).unwrap_or(0))
                    .sum::<u64>(),
            ));
            pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                ?
                .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
                .progress_chars("#>-"));

            // Async send the file contexts
            tokio::spawn(async move {
                for (i, file_path) in files.iter().enumerate() {
                    let (file_context, stream_reader) = FileContext::from_meta(
                        i,
                        file_path,
                        (Some(key), Some(key)),
                        recipient_keys.clone(),
                    )
                    .await?;

                    ctx_sender.send(Message::FileContext(file_context)).await?;
                    stream_sender.send(stream_reader).await?;
                }

                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });

            let pb_clone = pb.clone();

            // Send all file data into channel
            let (data_sender, data_receiver) = async_channel::bounded(100); // Channel cap?
            tokio::spawn(async move {
                loop {
                    match stream_receiver.try_recv() {
                        Ok(mut input_stream) => {
                            while let Some(bytes) = input_stream.next().await {
                                pb_clone.inc(bytes.as_ref().map(|a| a.len()).unwrap_or(0) as u64);
                                data_sender.send(Ok(bytes?)).await?
                            }
                        }
                        Err(TryRecvError::Empty) => {
                            // Do nothing. Try again.
                        }
                        Err(TryRecvError::Closed) => break, // No more input streams available
                    }
                }
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });
            pin!(data_receiver);

            // Init default PithosWriter with standard Transformers
            let mut writer = if let Some(output_path) = cli.output {
                PithosWriter::new_with_writer(
                    data_receiver,
                    File::create(output_path).await?,
                    ctx_receiver,
                    private_key,
                )
                .await?
            } else {
                PithosWriter::new_with_writer(
                    data_receiver,
                    tokio::io::stdout(),
                    ctx_receiver,
                    private_key,
                )
                .await?
            };
            writer.process_bytes().await?;
        }
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
