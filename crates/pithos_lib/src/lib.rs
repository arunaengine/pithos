mod crypt4gh;
pub mod helpers;
pub mod pithos;
pub mod readwrite;
pub mod streamreadwrite;
pub mod transformer;
pub mod transformers;

#[cfg(test)]
mod tests {
    use std::io::SeekFrom;

    use crate::helpers::footer_parser::{Footer, FooterParser, FooterParserState};
    use crate::helpers::notifications::{DirOrFileIdx, Message};
    use crate::helpers::structs::{EncryptionKey, FileContext, Range};
    use crate::pithos::structs::FileContextVariants;
    use crate::readwrite::GenericReadWriter;
    use crate::streamreadwrite::GenericStreamReadWriter;
    use crate::transformer::ReadWriter;
    use crate::transformers::decrypt::ChaCha20Dec;
    use crate::transformers::decrypt_resilient::ChaChaResilient;
    use crate::transformers::decrypt_with_parts::ChaCha20DecParts;
    use crate::transformers::encrypt::{encrypt_chunk, ChaCha20Enc};
    use crate::transformers::filter::Filter;
    use crate::transformers::footer::FooterGenerator;
    use crate::transformers::footer_extractor::FooterExtractor;
    use crate::transformers::footer_updater::FooterUpdater;
    use crate::transformers::gzip_comp::GzipEnc;
    use crate::transformers::hashing_transformer::HashingTransformer;
    use crate::transformers::pithos_comp_enc::PithosTransformer;
    use crate::transformers::size_probe::SizeProbe;
    use crate::transformers::tar::TarEnc;
    use crate::transformers::zstd_comp::ZstdEnc;
    use crate::transformers::zstd_decomp::ZstdDec;
    use base64::prelude::*;
    use bytes::Bytes;
    use digest::Digest;
    use futures::{StreamExt, TryStreamExt};
    use md5::Md5;
    use sha2::Sha256;
    use tempfile::TempDir;
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    #[tokio::test]
    async fn e2e_compressor_test_with_file() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.comp");
        let out_file = File::create(&out_path).await.unwrap();
        let in_file = File::open("test.txt").await.unwrap();

        // Create a new GenericReadWriter to compress and decompress the input
        GenericReadWriter::new_with_writer(in_file, out_file)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();

        // Assert that input and output is equal
        let mut original_file = File::open("test.txt").await.unwrap();
        let mut original_bytes = String::new();
        original_file
            .read_to_string(&mut original_bytes)
            .await
            .unwrap();

        let mut also_original_file = File::open(out_path).await.unwrap();
        let mut also_original_bytes = String::new();
        also_original_file
            .read_to_string(&mut also_original_bytes)
            .await
            .unwrap();

        assert_eq!(original_bytes, also_original_bytes)
    }

    #[tokio::test]
    async fn e2e_encrypt_test_with_vec_no_pad() {
        let input = b"This is a very very important test".to_vec();
        let mut output = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(input.as_ref(), &mut output)
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        assert_eq!(input, output);
    }

    #[tokio::test]
    async fn e2e_encrypt_test_with_file_no_pad() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let file_out = File::create(&out_path).await.unwrap();
        let file_in = File::open("test.txt").await.unwrap();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file_in, file_out)
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        let mut original_file = File::open("test.txt").await.unwrap();
        let mut also_original_file = File::open(out_path).await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        original_file.read_to_string(&mut buf1).await.unwrap();
        also_original_file.read_to_string(&mut buf2).await.unwrap();

        assert_eq!(buf1, buf2)
    }

    #[tokio::test]
    async fn e2e_test_roundtrip_with_file() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let file_out = File::create(&out_path).await.unwrap();
        let file_in = File::open("test.txt").await.unwrap();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file_in, file_out)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open(out_path).await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();

        assert_eq!(buf1, buf2)
    }

    #[tokio::test]
    async fn test_with_vec() {
        let input = b"This is a very very important test".to_vec();
        let mut output = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(input.as_ref(), &mut output)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdEnc::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new()) // Double decompression because we can
            .process()
            .await
            .unwrap();

        assert_eq!(input, output)
    }

    #[tokio::test]
    async fn test_footer_parsing() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let file_out = File::create(&out_path).await.unwrap();
        let file_in = File::open("test.txt").await.unwrap();

        GenericReadWriter::new_with_writer(file_in, file_out)
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                FooterGenerator::new_with_ctx(FileContext {
                    file_path: "test.txt".to_string(),
                    ..Default::default()
                })
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        let mut footer_file = File::open(out_path).await.unwrap();
        footer_file.seek(SeekFrom::End(-65536 * 2)).await.unwrap();

        let buf: &mut [u8; 65536 * 2] = &mut [0; 65536 * 2];
        footer_file.read_exact(buf).await.unwrap();

        let mut fp = FooterParser::new(buf).unwrap();
        fp = fp.parse().unwrap();

        assert!(matches!(fp.state, FooterParserState::Decoded))
    }

    #[tokio::test]
    async fn test_footer_parsing_encrypted() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let file_out = File::create(&out_path).await.unwrap();
        let file_in = File::open("test.txt").await.unwrap();

        // Compression + Encryption + Footer
        GenericReadWriter::new_with_writer(file_in, file_out)
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                FooterGenerator::new_with_ctx(FileContext {
                    file_path: "test.txt".to_string(),
                    encryption_key: EncryptionKey::Same(
                        b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                            .to_vec()
                            .try_into()
                            .unwrap(),
                    ),
                    ..Default::default()
                })
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        let mut footer_file = File::open(out_path).await.unwrap();
        footer_file
            .seek(SeekFrom::End((-65536 - 28) * 2))
            .await
            .unwrap();

        let buf: &mut [u8; (65536 + 28) * 2] = &mut [0; (65536 + 28) * 2];
        footer_file.read_exact(buf).await.unwrap();

        let mut fp = FooterParser::new(buf).unwrap();
        fp = fp.add_recipient(b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea");
        fp = fp.parse().unwrap();
        assert!(matches!(fp.state, FooterParserState::Decoded));

        let _: Footer = fp.try_into().unwrap();
    }

    #[tokio::test]
    async fn test_simple_filter_range() {
        // Filter from start
        let input1 = b"This is a very very important test".to_vec();
        let mut output_01 = Vec::new();
        GenericReadWriter::new_with_writer(input1.as_ref(), &mut output_01)
            .add_transformer(Filter::new_with_range(Range { from: 0, to: 3 }))
            .process()
            .await
            .unwrap();
        assert_eq!(output_01, b"Thi".to_vec());

        // Filter in middle
        let input2 = b"This is a very very important test".to_vec();
        let mut output_02 = Vec::new();
        GenericReadWriter::new_with_writer(input2.as_ref(), &mut output_02)
            .add_transformer(Filter::new_with_range(Range { from: 6, to: 16 }))
            .process()
            .await
            .unwrap();
        assert_eq!(output_02, b"s a very v".to_vec());

        // Filter until end
        let input3 = b"This is a very very important test".to_vec();
        let mut output_03 = Vec::new();
        GenericReadWriter::new_with_writer(input3.as_ref(), &mut output_03)
            .add_transformer(Filter::new_with_range(Range {
                from: 25,
                to: input3.len() as u64,
            }))
            .process()
            .await
            .unwrap();
        assert_eq!(output_03, b"tant test".to_vec());
    }

    #[tokio::test]
    async fn test_complex_filter() {
        let input = b"This is a very very important test".to_vec();
        let mut output = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(input.as_ref(), &mut output)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdEnc::new()) // Double compression because we can
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"99wj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .add_transformer(ZstdDec::new())
            .add_transformer(Filter::new_with_range(Range { from: 0, to: 3 }))
            .process()
            .await
            .unwrap();

        assert_eq!(output, b"Thi".to_vec());
    }

    #[tokio::test]
    async fn test_read_write_multifile() {
        let file1 = b"Lorem ipsum dolor sit amet, consetetur sadipscing elitr.".to_vec();
        let file2 = b"Stet clita kasd gubergren, no sea takimata sanctus.".to_vec();
        let mut output: Vec<u8> = Vec::new();

        let combined = Vec::from_iter(file1.clone().into_iter().chain(file2.clone()));

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1.len() as u64,
            decompressed_size: file1.len() as u64,
            compression: true,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2.len() as u64,
            decompressed_size: file2.len() as u64,
            compression: false,
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericReadWriter
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut output);
        aswr.add_message_receiver(rx).await.unwrap();
        aswr = aswr
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(ZstdDec::new());
        aswr.process().await.unwrap();
        drop(aswr);

        assert_eq!(output, combined);
    }

    #[tokio::test]
    async fn stream_test() {
        use futures::stream;

        let bytes_stream = stream::iter(vec![
            Ok(Bytes::from(
                b"One morning, when Gregor Samsa woke from troubled dreams, ".to_vec(),
            )),
            Ok(Bytes::from(
                b"he found himself transformed in his bed into a horrible vermin.".to_vec(),
            )),
        ]);

        // Create a new GenericStreamReadWriter
        let mut output = Vec::new();
        GenericStreamReadWriter::new_with_writer(bytes_stream, &mut output)
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(
                ChaCha20Dec::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();

        assert_eq!(
            output,
            b"One morning, when Gregor Samsa woke from troubled dreams, he found himself transformed in his bed into a horrible vermin.".to_vec()
        );
    }

    #[tokio::test]
    async fn e2e_test_read_write_multifile_tar_small() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let mut file_out = File::create(&out_path).await.unwrap();

        let file1 = b"The quick, brown fox jumps over a lazy dog.".to_vec();
        let file2 =
            b"Junk MTV quiz graced by fox whelps. Bawds jog, flick quartz, vex nymphs.".to_vec();
        let combined = Vec::from_iter(file1.clone().into_iter().chain(file2.clone()));

        // File context input
        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1.len() as u64,
            decompressed_size: file1.len() as u64,
            compression: true,
            encryption_key: EncryptionKey::Same(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2.len() as u64,
            decompressed_size: file2.len() as u64,
            compression: false,
            encryption_key: EncryptionKey::Same(
                b"xxwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericReadWriter
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut file_out)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_read_write_multifile_tar_real() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let mut file_out = File::create(&out_path).await.unwrap();

        let mut file1 = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt").await.unwrap();
        let mut combined = Vec::new();
        file1.read_to_end(&mut combined).await.unwrap();
        file2.read_to_end(&mut combined).await.unwrap();

        // File context input
        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1.metadata().await.unwrap().len(),
            decompressed_size: file1.metadata().await.unwrap().len(),
            compression: true,
            encryption_key: EncryptionKey::Same(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2.metadata().await.unwrap().len(),
            decompressed_size: file2.metadata().await.unwrap().len(),
            compression: false,
            encryption_key: EncryptionKey::Same(
                b"xxwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericReadWriter
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut file_out)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_stream_write_multifile_tar_real() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let mut file_out = File::create(&out_path).await.unwrap();

        let file1 = File::open("test.txt").await.unwrap();
        let file2 = File::open("test.txt").await.unwrap();
        let file1_size = file1.metadata().await.unwrap().len();
        let file2_size = file2.metadata().await.unwrap().len();
        let stream1 = tokio_util::io::ReaderStream::new(file1);
        let stream2 = tokio_util::io::ReaderStream::new(file2);
        let chained = stream1.chain(stream2);
        let mapped = chained.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        // File context input
        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1_size,
            decompressed_size: file1_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2_size,
            decompressed_size: file2_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file_out)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_stream_tar_gz() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let mut file_out = File::create(&out_path).await.unwrap();

        let file1 = File::open("test.txt").await.unwrap();
        let file2 = File::open("test.txt").await.unwrap();
        let file1_size = file1.metadata().await.unwrap().len();
        let file2_size = file2.metadata().await.unwrap().len();
        let stream1 = tokio_util::io::ReaderStream::new(file1);
        let stream2 = tokio_util::io::ReaderStream::new(file2);
        let chained = stream1.chain(stream2);
        let mapped = chained.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1_size,
            decompressed_size: file1_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2_size,
            decompressed_size: file2_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file_out)
            .add_transformer(TarEnc::new())
            .add_transformer(GzipEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn hashing_transformer_test() {
        let input = b"Lorem ipsum dolor sit amet, consectetuer adipiscing elit.".to_vec();
        let mut output = Vec::new();

        let (size_probe, rx) = SizeProbe::new();
        let (md5_transformer, md5_rcv) =
            HashingTransformer::new_with_backchannel(Md5::new(), "md5".to_string());
        let (sha256_transformer, sha256_rcv) =
            HashingTransformer::new_with_backchannel(Sha256::new(), "sha256".to_string());

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(input.as_ref(), &mut output)
            .add_transformer(size_probe)
            .add_transformer(md5_transformer)
            .add_transformer(sha256_transformer)
            .process()
            .await
            .unwrap();

        let size = rx.try_recv().unwrap();
        assert_eq!(size, 57);

        let md5 = md5_rcv.try_recv().unwrap();
        assert_eq!(md5, "a84e9dae73341f1e9764f349701a5adf".to_string());

        let sha256 = sha256_rcv.try_recv().unwrap();
        assert_eq!(
            sha256,
            "1d32dc481e105799b079b5a1b18c2e302bc43bc5feac01450c7ffa50a1c65b92".to_string()
        );
    }

    #[tokio::test]
    async fn e2e_test_stream_tar_folder() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let out_path = temp_dir.path().join("test.txt.out");
        let mut file_out = File::create(&out_path).await.unwrap();

        let file1 = File::open("test.txt").await.unwrap();
        let file2 = File::open("test.txt").await.unwrap();
        let file1_size = file1.metadata().await.unwrap().len();
        let file2_size = file2.metadata().await.unwrap().len();
        let stream1 = tokio_util::io::ReaderStream::new(file1);
        let stream2 = tokio_util::io::ReaderStream::new(file2);
        let chained = stream1.chain(stream2);
        let mapped = chained.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        // File context input
        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "blup/".to_string(),
            compressed_size: 0,
            decompressed_size: 0,
            is_dir: true,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "blup/file1.txt".to_string(),
            compressed_size: file1_size,
            decompressed_size: file1_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "blip/".to_string(),
            compressed_size: 0,
            decompressed_size: 0,
            is_dir: true,
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "blip/file2.txt".to_string(),
            compressed_size: file2_size,
            decompressed_size: file2_size,
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file_out)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_pithos_tar_gz() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let pithos_out_path = temp_dir.path().join("test.txt.out.pto");
        let tar_gz_out_path = temp_dir.path().join("test.txt.out.tar.gz");
        let mut pithos_out = File::create(&pithos_out_path).await.unwrap();

        let file1 = File::open("test.txt").await.unwrap();
        let file2 = File::open("test.txt").await.unwrap();
        let file1_size = file1.metadata().await.unwrap().len();
        let file2_size = file2.metadata().await.unwrap().len();
        let stream1 = tokio_util::io::ReaderStream::new(file1);
        let stream2 = tokio_util::io::ReaderStream::new(file2);
        let chained = stream1.chain(stream2);
        let mapped = chained.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        // File context input
        let (sx, rx) = async_channel::bounded(10);
        let privkey_bytes = BASE64_STANDARD
            .decode("MC4CAQAwBQYDK2VuBCIEIFDnbf0aEpZxwEdy1qG4xpV8gVNq7zEREtMjLzCE6R5x")
            .unwrap();
        let privkey: [u8; 32] = privkey_bytes[privkey_bytes.len() - 32..]
            .to_vec()
            .try_into()
            .unwrap();

        let pubkey_bytes = BASE64_STANDARD
            .decode("MCowBQYDK2VuAyEA2laqNukb4+2am7QdC6eDANu1DDuKdC5LPtYQM+XE5k8=")
            .unwrap();
        let pubkey: [u8; 32] = pubkey_bytes[pubkey_bytes.len() - 32..]
            .to_vec()
            .try_into()
            .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: file1_size,
            decompressed_size: file1_size,
            recipients_pubkeys: vec![pubkey],
            encryption_key: EncryptionKey::Same(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        sx.send(Message::FileContext(FileContext {
            file_path: "file2.txt".to_string(),
            compressed_size: file2_size,
            decompressed_size: file2_size,
            recipients_pubkeys: vec![pubkey],
            encryption_key: EncryptionKey::Same(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut pithos_out)
            .add_transformer(PithosTransformer::new())
            .add_transformer(FooterGenerator::new(None));
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();

        // Parse Footer
        let mut pithos_in = File::open(&pithos_out_path).await.unwrap();
        let file_meta = pithos_in.metadata().await.unwrap();
        let footer_prediction = if file_meta.len() < 65536 * 2 {
            file_meta.len() // 131072 always fits in i64 ...
        } else {
            65536 * 2
        };

        // Read footer bytes in FooterParser
        pithos_in
            .seek(SeekFrom::End(-(footer_prediction as i64)))
            .await
            .unwrap();
        let buf = &mut vec![0; footer_prediction as usize];
        pithos_in.read_exact(buf).await.unwrap();

        let mut parser = FooterParser::new(buf).unwrap();
        parser = parser.add_recipient(&privkey);
        parser = parser.parse().unwrap();

        // Check if bytes are missing
        let mut missing_buf;
        if let FooterParserState::Missing(missing_bytes) = parser.state {
            let needed_bytes = footer_prediction + missing_bytes as u64;
            pithos_in
                .seek(SeekFrom::End(-(needed_bytes as i64)))
                .await
                .unwrap();
            missing_buf = vec![0; missing_bytes];
            pithos_in.read_exact(&mut missing_buf).await.unwrap();

            parser = parser.add_bytes(&missing_buf).unwrap();
            parser = parser.parse().unwrap()
        }

        // Parse the footer bytes and display Table of Contents
        let footer: Footer = parser.try_into().unwrap();

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

        let mut tar_gz_file = File::create(&tar_gz_out_path).await.unwrap();
        let read_stream = tokio_util::io::ReaderStream::new(pithos_in).map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        let (sx2, rx2) = async_channel::bounded(10);
        let mut reader = GenericStreamReadWriter::new_with_writer(read_stream, &mut tar_gz_file)
            .add_transformer(ChaCha20Dec::new_with_fixed_list(keys).unwrap())
            .add_transformer(ZstdDec::new())
            .add_transformer(TarEnc::new())
            .add_transformer(GzipEnc::new());
        reader.add_message_receiver(rx2).await.unwrap();

        for (idx, file) in footer.table_of_contents.files.into_iter().enumerate() {
            if let FileContextVariants::FileDecrypted(file) = file {
                sx2.send(Message::FileContext(
                    file.try_into_file_context(idx).unwrap(),
                ))
                .await
                .unwrap();
            }
        }
        reader.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_pithos_rewrite_footer() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let pithos_out_path1 = temp_dir.path().join("test.txt.out.pto");
        let pithos_out_path2 = temp_dir.path().join("test.txt.out.upd.pto");
        let mut pithos_out = File::create(&pithos_out_path1).await.unwrap();

        let input_file = File::open("test.txt").await.unwrap();
        let input_size = input_file.metadata().await.unwrap().len();
        let input_stream = tokio_util::io::ReaderStream::new(input_file).map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        // File context input
        let privkey_bytes = BASE64_STANDARD
            .decode("MC4CAQAwBQYDK2VuBCIEIFDnbf0aEpZxwEdy1qG4xpV8gVNq7zEREtMjLzCE6R5x")
            .unwrap();
        let privkey: [u8; 32] = privkey_bytes[privkey_bytes.len() - 32..]
            .to_vec()
            .try_into()
            .unwrap();

        let pubkey_bytes = BASE64_STANDARD
            .decode("MCowBQYDK2VuAyEA2laqNukb4+2am7QdC6eDANu1DDuKdC5LPtYQM+XE5k8=")
            .unwrap();
        let pubkey: [u8; 32] = pubkey_bytes[pubkey_bytes.len() - 32..]
            .to_vec()
            .try_into()
            .unwrap();

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: input_size,
            decompressed_size: input_size,
            recipients_pubkeys: vec![pubkey],
            encryption_key: EncryptionKey::Same(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(input_stream, &mut pithos_out)
            .add_transformer(PithosTransformer::new())
            .add_transformer(FooterGenerator::new(None));
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();

        // Parse Footer
        let mut pithos_input = File::open(&pithos_out_path1).await.unwrap();
        let file_meta = pithos_input.metadata().await.unwrap();

        let footer_prediction = if file_meta.len() < 65536 * 2 {
            file_meta.len() // 131072 always fits in i64 ...
        } else {
            65536 * 2
        };

        // Read footer bytes in FooterParser
        pithos_input
            .seek(SeekFrom::End(-(footer_prediction as i64)))
            .await
            .unwrap();
        let buf = &mut vec![0; footer_prediction as usize];
        pithos_input.read_exact(buf).await.unwrap();

        let mut parser = FooterParser::new(buf).unwrap();
        parser = parser.add_recipient(&privkey);
        parser = parser.parse().unwrap();

        // Check if bytes are missing
        let mut missing_buf;
        if let FooterParserState::Missing(missing_bytes) = parser.state {
            let needed_bytes = footer_prediction + missing_bytes as u64;
            pithos_input
                .seek(SeekFrom::End(-(needed_bytes as i64)))
                .await
                .unwrap();
            missing_buf = vec![0; missing_bytes];
            pithos_input.read_exact(&mut missing_buf).await.unwrap();

            parser = parser.add_bytes(&missing_buf).unwrap();
            parser = parser.parse().unwrap()
        }

        // Parse the footer bytes and display Table of Contents ...
        let footer: Footer = parser.try_into().unwrap();

        // Create reader stream for Pithos file
        pithos_input.seek(SeekFrom::Start(0)).await.unwrap();
        let read_stream = tokio_util::io::ReaderStream::new(pithos_input).map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        let privkey_bytes_2 = BASE64_STANDARD
            .decode("MC4CAQAwBQYDK2VuBCIEIMhHHRAu72qdkx9I4D08RD3OQniJxGUI420aPlZwAJtX")
            .unwrap();
        let privkey_2: [u8; 32] = privkey_bytes_2[privkey_bytes_2.len() - 32..]
            .to_vec()
            .try_into()
            .unwrap();

        let pubkey_bytes_2 = BASE64_STANDARD
            .decode("MCowBQYDK2VuAyEAoqu7pzwam2uks5EseS06jQP6ISX42f613KKWm8cLM1M=")
            .unwrap();
        let pubkey_2: [u8; 32] = pubkey_bytes_2[pubkey_bytes_2.len() - 32..]
            .to_vec()
            .try_into()
            .unwrap();

        let (_, rx2) = async_channel::bounded(10);
        let mut pithos_out_2 = File::create(&pithos_out_path2).await.unwrap();
        let mut reader = GenericStreamReadWriter::new_with_writer(read_stream, &mut pithos_out_2)
            .add_transformer(FooterUpdater::new(vec![pubkey_2], footer));
        reader.add_message_receiver(rx2).await.unwrap();
        reader.process().await.unwrap();

        // Parse Footer
        let mut pithos_input = File::open(pithos_out_path2).await.unwrap();
        let file_meta = pithos_input.metadata().await.unwrap();

        let footer_prediction = if file_meta.len() < 65536 * 2 {
            file_meta.len() // 131072 always fits in i64 ...
        } else {
            65536 * 2
        };

        // Read footer bytes in FooterParser
        pithos_input
            .seek(SeekFrom::End(-(footer_prediction as i64)))
            .await
            .unwrap();
        let buf = &mut vec![0; footer_prediction as usize]; // Has to be vec as length is defined by dynamic value
        pithos_input.read_exact(buf).await.unwrap();

        let mut parser = FooterParser::new(buf).unwrap();
        parser = parser.add_recipient(&privkey_2);
        parser = parser.parse().unwrap();

        let footer: Footer = parser.try_into().unwrap();
        assert!(footer.encryption_keys.unwrap().keys.len() > 0)
    }

    #[tokio::test]
    async fn e2e_pithos_extractor() {
        // File handling
        let temp_dir = TempDir::new().unwrap();
        let pithos_out_path = temp_dir.path().join("test.txt.pto");
        let mut pithos_out = File::create(&pithos_out_path).await.unwrap();

        let input_file = File::open("test.txt").await.unwrap();
        let input_size = input_file.metadata().await.unwrap().len();
        let input_stream = tokio_util::io::ReaderStream::new(input_file).map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        // File context input
        let privkey_bytes = BASE64_STANDARD
            .decode("MC4CAQAwBQYDK2VuBCIEIFDnbf0aEpZxwEdy1qG4xpV8gVNq7zEREtMjLzCE6R5x")
            .unwrap();
        let privkey: [u8; 32] = privkey_bytes[privkey_bytes.len() - 32..]
            .to_vec()
            .try_into()
            .unwrap();

        let pubkey_bytes = BASE64_STANDARD
            .decode("MCowBQYDK2VuAyEA2laqNukb4+2am7QdC6eDANu1DDuKdC5LPtYQM+XE5k8=")
            .unwrap();
        let pubkey: [u8; 32] = pubkey_bytes[pubkey_bytes.len() - 32..]
            .to_vec()
            .try_into()
            .unwrap();

        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "file1.txt".to_string(),
            compressed_size: input_size,
            decompressed_size: input_size,
            recipients_pubkeys: vec![pubkey],
            encryption_key: EncryptionKey::Same(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(input_stream, &mut pithos_out)
            .add_transformer(PithosTransformer::new())
            .add_transformer(FooterGenerator::new(None));
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();

        // Parse Footer
        let mut pithos_input = File::open(pithos_out_path).await.unwrap();
        let file_meta = pithos_input.metadata().await.unwrap();

        let footer_prediction = if file_meta.len() < 65536 * 2 {
            file_meta.len() // 131072 always fits in i64 ...
        } else {
            65536 * 2
        };

        // Read footer bytes in FooterParser
        pithos_input
            .seek(SeekFrom::End(-(footer_prediction as i64)))
            .await
            .unwrap();
        let buf = &mut vec![0; footer_prediction as usize];
        pithos_input.read_exact(buf).await.unwrap();

        let mut parser = FooterParser::new(buf).unwrap();
        parser = parser.add_recipient(&privkey);
        parser = parser.parse().unwrap();

        // Parse the footer bytes and display Table of Contents
        let footer: Footer = parser.try_into().unwrap();

        // Read footer with FooterExtractor
        let mut vec = Vec::new();
        pithos_input.seek(SeekFrom::Start(0)).await.unwrap();
        let input_stream = tokio_util::io::ReaderStream::new(pithos_input).map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        let (extractor, rcv) = FooterExtractor::new(Some(privkey));
        GenericStreamReadWriter::new_with_writer(input_stream, &mut vec)
            .add_transformer(extractor)
            .process()
            .await
            .unwrap();

        let extracted_footer = rcv.recv_blocking().unwrap();
        assert_eq!(extracted_footer, footer);
    }

    #[tokio::test]
    async fn e2e_test_parts_decryptor() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = vec![];

        let repeated: Vec<u64> = vec![65564u64 * 60, 65564 * 16, 65564, 50860];

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file, file2)
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .add_transformer(ChaCha20DecParts::new_with_lengths(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                repeated,
            ))
            .process()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn e2e_test_resilient_decryptor_no_lengths() {
        // Encrypt test file
        let temp_dir = TempDir::new().unwrap();
        let enc_file_path = temp_dir.path().join("test.txt.enc");

        let file_in = File::open("test.txt").await.unwrap();
        let mut enc_out = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&enc_file_path)
            .await
            .unwrap();

        GenericReadWriter::new_with_writer(file_in, &mut enc_out)
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        // Read encrypted parts in buffer
        let mut input = Vec::new();
        let mut enc_file = File::open(enc_file_path).await.unwrap();
        enc_file.read_to_end(&mut input).await.unwrap();

        // Create a new GenericReadWriter that decrypts the parts
        let mut output = vec![];
        let part_lengths: Vec<u64> = vec![];
        GenericReadWriter::new_with_writer(input.as_slice(), &mut output)
            .add_transformer(ChaChaResilient::new_with_lengths(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                part_lengths,
            ))
            .process()
            .await
            .unwrap();

        // Assert output is same as original file
        let mut original_file = File::open("test.txt").await.unwrap();
        let file_size = original_file.metadata().await.unwrap().len();
        assert_eq!(output.len() as u64, file_size);

        let mut original_bytes = Vec::new();
        original_file
            .read_to_end(&mut original_bytes)
            .await
            .unwrap();
        assert_eq!(output, original_bytes);
    }

    #[tokio::test]
    async fn e2e_test_resilient_decryptor_single() {
        // Encrypt single part
        let temp_dir = TempDir::new().unwrap();
        let part_1_path = temp_dir.path().join("test.1.txt.enc");
        let mut part_1_out = File::create(&part_1_path).await.unwrap();

        let mut input = File::open("test.txt").await.unwrap();
        let mut part_1_bytes = vec![0; 70113];
        input.read_exact(&mut part_1_bytes).await.unwrap();

        GenericReadWriter::new_with_writer(part_1_bytes.as_ref(), &mut part_1_out)
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        // Read encrypted part in buffer
        let mut input = Vec::new();
        let mut file_part_1 = File::open(part_1_path).await.unwrap();
        file_part_1.read_to_end(&mut input).await.unwrap();

        let mut output = vec![];
        let part_lengths: Vec<u64> = vec![part_1_bytes.len() as u64];

        // Create a new GenericReadWriter that decrypts the part
        GenericReadWriter::new_with_writer(input.as_slice(), &mut output)
            .add_transformer(ChaChaResilient::new_with_lengths(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                part_lengths,
            ))
            .process()
            .await
            .unwrap();

        assert_eq!(output, part_1_bytes);
    }

    #[tokio::test]
    async fn e2e_test_resilient_decryptor_multi() {
        // Create temp paths for encrypted parts
        let temp_dir = TempDir::new().unwrap();
        let part_1_path = temp_dir.path().join("test.1.txt.enc");
        let part_2_path = temp_dir.path().join("test.2.txt.enc");
        let mut input = File::open("test.txt").await.unwrap();

        // Encrypt parts individually
        let mut part_1_bytes = vec![0; 70113];
        input.read_exact(&mut part_1_bytes).await.unwrap();
        let part_1_out = File::create(&part_1_path).await.unwrap();

        let mut part_2_bytes = Vec::new();
        input.read_to_end(&mut part_2_bytes).await.unwrap();
        let part_2_out = File::create(&part_2_path).await.unwrap();

        for (input, mut output) in vec![
            (part_1_bytes.as_ref(), part_1_out),
            (part_2_bytes.as_ref(), part_2_out),
        ] {
            GenericReadWriter::new_with_writer(input, &mut output)
                .add_transformer(
                    ChaCha20Enc::new_with_fixed(
                        b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                            .to_vec()
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap(),
                )
                .process()
                .await
                .unwrap();
        }

        // Read encrypted parts in buffer
        let mut input = Vec::new();
        let mut file_part_1 = File::open(part_1_path).await.unwrap();
        file_part_1.read_to_end(&mut input).await.unwrap();
        let mut file_part_2 = File::open(part_2_path).await.unwrap();
        file_part_2.read_to_end(&mut input).await.unwrap();

        let mut output = vec![];
        let part_lengths: Vec<u64> = vec![4605, 46283];

        // Create a new GenericReadWriter that decrypts the parts
        GenericReadWriter::new_with_writer(input.as_slice(), &mut output)
            .add_transformer(ChaChaResilient::new_with_lengths(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                part_lengths,
            ))
            .process()
            .await
            .unwrap();

        // Assert output is same as original file
        let mut original_file = File::open("test.txt").await.unwrap();
        let file_size = original_file.metadata().await.unwrap().len();
        assert_eq!(output.len() as u64, file_size);

        let mut original_bytes = Vec::new();
        original_file
            .read_to_end(&mut original_bytes)
            .await
            .unwrap();
        assert_eq!(output, original_bytes);
    }

    #[tokio::test]
    async fn e2e_test_resilient_decryptor_multi_with_compression() {
        // Create temp paths for encrypted parts
        let temp_dir = TempDir::new().unwrap();
        let part_1_path = temp_dir.path().join("test.1.txt.enc");
        let part_2_path = temp_dir.path().join("test.2.txt.enc");
        let mut input = File::open("test.txt").await.unwrap();

        // Encrypt parts individually
        let mut part_1_bytes = vec![0; 70113];
        input.read_exact(&mut part_1_bytes).await.unwrap();
        let part_1_out = File::create(&part_1_path).await.unwrap();

        let mut part_2_bytes = Vec::new();
        input.read_to_end(&mut part_2_bytes).await.unwrap();
        let part_2_out = File::create(&part_2_path).await.unwrap();

        for (input, mut output) in vec![
            (part_1_bytes.as_ref(), part_1_out),
            (part_2_bytes.as_ref(), part_2_out),
        ] {
            GenericReadWriter::new_with_writer(input, &mut output)
                .add_transformer(ZstdEnc::new())
                .add_transformer(
                    ChaCha20Enc::new_with_fixed(
                        b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                            .to_vec()
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap(),
                )
                .process()
                .await
                .unwrap();
        }

        // Read encrypted parts in buffer
        let mut input = Vec::new();
        let mut file_part_1 = File::open(part_1_path).await.unwrap();
        let file_part_1_size = file_part_1.metadata().await.unwrap().len();
        file_part_1.read_to_end(&mut input).await.unwrap();

        let mut file_part_2 = File::open(part_2_path).await.unwrap();
        let file_part_2_size = file_part_2.metadata().await.unwrap().len();
        file_part_2.read_to_end(&mut input).await.unwrap();

        let mut output = vec![];
        let part_lengths: Vec<u64> = vec![file_part_1_size % 65564, file_part_2_size % 65564]; //vec![4605, 46283];

        // Create a new GenericReadWriter that decrypts the parts
        GenericReadWriter::new_with_writer(input.as_slice(), &mut output)
            .add_transformer(ChaChaResilient::new_with_lengths(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                part_lengths,
            ))
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();

        // Assert output is same as original file
        let mut original_file = File::open("test.txt").await.unwrap();
        let file_size = original_file.metadata().await.unwrap().len();
        assert_eq!(output.len() as u64, file_size);

        let mut original_bytes = Vec::new();
        original_file
            .read_to_end(&mut original_bytes)
            .await
            .unwrap();
        assert_eq!(output, original_bytes);
    }

    #[tokio::test]
    async fn transformer_output_comparison() {
        let original_file = File::open("test.txt").await.unwrap();
        let file_size = original_file.metadata().await.unwrap().len();

        // Compress and encrypt with ZstdEnc+ChaChaEnc
        let mut comp_enc_out = Vec::new();
        GenericReadWriter::new_with_writer(original_file, &mut comp_enc_out)
            .add_transformer(ZstdEnc::new())
            .add_transformer(
                ChaCha20Enc::new_with_fixed(
                    b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                        .to_vec()
                        .to_vec()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
            .process()
            .await
            .unwrap();

        // Compress and encrypt with PithosTransformer
        let (sx, rx) = async_channel::bounded(10);
        sx.send(Message::FileContext(FileContext {
            file_path: "test.txt".to_string(),
            compressed_size: file_size,
            decompressed_size: file_size,
            recipients_pubkeys: vec![],
            encryption_key: EncryptionKey::Same(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            ),
            ..Default::default()
        }))
        .await
        .unwrap();

        let original_file = File::open("test.txt").await.unwrap();
        let mut pithos_out = Vec::new();
        let mut aswr = GenericReadWriter::new_with_writer(original_file, &mut pithos_out)
            .add_transformer(PithosTransformer::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();

        drop(aswr);
        //assert_eq!(comp_enc_out.len(), pithos_out.len())

        let mut decrypted1 = Vec::new();
        // Create a new GenericReadWriter that decrypts the parts
        GenericReadWriter::new_with_writer(comp_enc_out.as_slice(), &mut decrypted1)
            .add_transformer(ChaChaResilient::new_with_lengths(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                vec![comp_enc_out.len() as u64],
            ))
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();
        assert_eq!(file_size, decrypted1.len() as u64);

        let mut decrypted2 = Vec::new();
        // Create a new GenericReadWriter that decrypts the parts
        GenericReadWriter::new_with_writer(pithos_out.as_slice(), &mut decrypted2)
            .add_transformer(ChaChaResilient::new_with_lengths(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                vec![pithos_out.len() as u64],
            ))
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();
        assert_eq!(file_size, decrypted2.len() as u64);

        assert_eq!(decrypted1, decrypted2);
    }

    #[tokio::test]
    async fn e2e_test_resilient_decryptor_single_chunk() {
        // Encrypt test file in single chunk
        let mut file_in = File::open("test.txt").await.unwrap();
        let mut file_bytes = Vec::new();
        file_in.read_to_end(&mut file_bytes).await.unwrap();

        let encrypted_bytes =
            encrypt_chunk(&file_bytes, b"", b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea", false).unwrap();

        // Create a new GenericReadWriter that decrypts the parts
        let mut output = vec![];
        let part_lengths: Vec<u64> = vec![encrypted_bytes.len() as u64]; //vec![5099288];
        GenericReadWriter::new_with_writer(encrypted_bytes.to_vec().as_slice(), &mut output)
            .add_transformer(ChaChaResilient::new_with_lengths(
                b"wvwj3485nxgyq5ub9zd3e7jsrq7a92ea"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                part_lengths,
            ))
            .process()
            .await
            .unwrap();

        // Assert output is same as original file
        assert_eq!(file_bytes.len(), output.len());
        assert_eq!(output, file_bytes);
    }
}
