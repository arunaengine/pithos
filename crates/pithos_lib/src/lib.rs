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
    //use crate::helpers::footer_parser::{FooterParser, Range};
    use crate::helpers::notifications::{DirOrFileIdx, Message};
    use crate::helpers::structs::{EncryptionKey, FileContext, Range};
    use crate::pithos::structs::FileContextVariants;
    use crate::readwrite::GenericReadWriter;
    use crate::streamreadwrite::GenericStreamReadWriter;
    use crate::transformer::ReadWriter;
    use crate::transformers::decrypt::ChaCha20Dec;
    use crate::transformers::decrypt_resilient::ChaChaResilient;
    use crate::transformers::decrypt_with_parts::ChaCha20DecParts;
    use crate::transformers::encrypt::ChaCha20Enc;
    use crate::transformers::filter::Filter;
    use crate::transformers::footer::FooterGenerator;
    use crate::transformers::footer_extractor::FooterExtractor;
    use crate::transformers::footer_updater::FooterUpdater;
    use crate::transformers::gzip_comp::GzipEnc;
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
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    #[tokio::test]
    async fn e2e_compressor_test_with_file() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.1").await.unwrap();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file, file2)
            .add_transformer(ZstdEnc::new())
            .add_transformer(ZstdDec::new())
            .process()
            .await
            .unwrap();

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt.out.1").await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf1 == buf2)
    }

    #[tokio::test]
    async fn e2e_encrypt_test_with_vec_no_pad() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
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

        assert_eq!(file, file2);
    }

    #[tokio::test]
    async fn e2e_encrypt_test_with_file_no_pad() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.2").await.unwrap();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file, file2)
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

        let mut file = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt.out.2").await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf1 == buf2)
    }

    #[tokio::test]
    async fn e2e_test_roundtrip_with_file() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.4").await.unwrap();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file, file2)
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
        let mut file2 = File::open("test.txt.out.4").await.unwrap();
        let mut buf1 = String::new();
        let mut buf2 = String::new();
        file.read_to_string(&mut buf1).await.unwrap();
        file2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf1 == buf2)
    }

    #[tokio::test]
    async fn test_with_vec() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
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
        assert!(file == file2)
    }

    #[tokio::test]
    async fn test_footer_parsing() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.6").await.unwrap();
        GenericReadWriter::new_with_writer(file, file2)
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

        let mut file2 = File::open("test.txt.out.6").await.unwrap();
        file2
            .seek(std::io::SeekFrom::End(-65536 * 2))
            .await
            .unwrap();

        let buf: &mut [u8; 65536 * 2] = &mut [0; 65536 * 2];
        file2.read_exact(buf).await.unwrap();

        //let mut fp = FooterParser::new(buf);

        //fp.parse().unwrap();

        // let (a, b) = fp
        //     .get_offsets_by_range(Range { from: 0, to: 1000 })
        //     .unwrap();

        // assert!(a.to % (65536) == 0);

        // assert_eq!(
        //     a,
        //     Range {
        //         from: 0,
        //         to: 25 * 65536
        //     }
        // );
        // assert!(b == Range { from: 0, to: 1000 })
    }

    #[tokio::test]
    async fn test_footer_parsing_encrypted() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = File::create("test.txt.out.7").await.unwrap();
        GenericReadWriter::new_with_writer(file, file2)
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

        let mut file2 = File::open("test.txt.out.7").await.unwrap();
        file2
            .seek(std::io::SeekFrom::End((-65536 - 28) * 2))
            .await
            .unwrap();

        let buf: &mut [u8; (65536 + 28) * 2] = &mut [0; (65536 + 28) * 2];
        file2.read_exact(buf).await.unwrap();

        // let mut fp = FooterParser::new(buf);
        // fp.parse().unwrap();

        // let (a, b) = fp
        //     .get_offsets_by_range(Range { from: 0, to: 1000 })
        //     .unwrap();

        // assert!(a.to % (65536 + 28) == 0);

        // assert!(
        //     a == Range {
        //         from: 0,
        //         to: 25 * (65536 + 28)
        //     }
        // );
        // assert!(b == Range { from: 0, to: 1000 })
    }

    #[tokio::test]
    async fn test_with_filter() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
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

        println!("{:?}", file2);
        assert_eq!(file2, b"Thi".to_vec());
    }

    #[tokio::test]
    async fn test_read_write_multifile() {
        let file1 = b"This is a very very important test".to_vec();
        let file2 = b"This is a very very important test".to_vec();
        let mut file3: Vec<u8> = Vec::new();

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
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut file3);
        aswr.add_message_receiver(rx).await.unwrap();
        aswr = aswr
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
            .add_transformer(Filter::new_with_range(Range { from: 0, to: 3 }));
        aswr.process().await.unwrap();
        drop(aswr);

        println!("{:?}", file3);
        assert_eq!(file3, b"Thi".to_vec());
    }

    #[tokio::test]
    async fn stream_test() {
        let mut file2 = Vec::new();

        use futures::stream;

        let stream = stream::iter(vec![
            Ok(Bytes::from_iter(
                b"This is a very very important test".to_vec(),
            )),
            Ok(Bytes::from(b"This is a very very important test".to_vec())),
        ]);

        // Create a new GenericStreamReadWriter
        GenericStreamReadWriter::new_with_writer(stream, &mut file2)
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

        dbg!(format!("{:?}", std::str::from_utf8(&file2)));
        assert_eq!(file2, b"Thi".to_vec());
    }

    #[tokio::test]
    async fn e2e_test_read_write_multifile_tar_small() {
        let file1 = b"This is a very very important test".to_vec();
        let file2 = b"Another brilliant This is a very very important test1337".to_vec();
        let mut file3 = File::create("test.txt.out.8.tar").await.unwrap();

        let combined = Vec::from_iter(file1.clone().into_iter().chain(file2.clone()));

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
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut file3)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_read_write_multifile_tar_real() {
        let mut file1 = File::open("test.txt").await.unwrap();
        let mut file2 = File::open("test.txt").await.unwrap();
        let mut file3 = File::create("test.txt.out.9.tar").await.unwrap();

        let mut combined = Vec::new();
        file1.read_to_end(&mut combined).await.unwrap();
        file2.read_to_end(&mut combined).await.unwrap();

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
        let mut aswr = GenericReadWriter::new_with_writer(combined.as_ref(), &mut file3)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_stream_write_multifile_tar_real() {
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
        let mut file3 = File::create("test.txt.out.10").await.unwrap();

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
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_test_stream_tar_gz() {
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
        let mut file3 = File::create("test.txt.out.11").await.unwrap();

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
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(TarEnc::new())
            .add_transformer(GzipEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn hashing_transformer_test() {
        let file = b"This is a very very important test".to_vec();
        let mut file2 = Vec::new();

        let (probe, rx) = SizeProbe::new();
        let md5_trans = crate::transformers::hashing_transformer::HashingTransformer::new(
            Md5::new(),
            "md5".to_string(),
            false,
        );

        // Create a new GenericReadWriter
        GenericReadWriter::new_with_writer(file.as_ref(), &mut file2)
            .add_transformer(md5_trans)
            .add_transformer(probe)
            .process()
            .await
            .unwrap();

        let size = rx.try_recv().unwrap();
        //let md5 = rx2.try_recv().unwrap();
        // Todo: Receive MD5

        assert_eq!(size, 34);
        //assert_eq!(md5, "4f276870b4b5f84c0b2bbfce30757176".to_string());
    }

    #[tokio::test]
    async fn e2e_test_stream_tar_folder() {
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
        let mut file3 = File::create("test.txt.out.tar").await.unwrap();

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
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(TarEnc::new());
        aswr.add_message_receiver(rx).await.unwrap();
        //.add_transformer(GzipEnc::new());
        aswr.process().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_pithos_tar_gz() {
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
        let mut file3 = File::create("test.txt.out.pto").await.unwrap();

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
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(PithosTransformer::new())
            .add_transformer(FooterGenerator::new(None));
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();

        let mut file3 = File::open("test.txt.out.pto").await.unwrap();

        // Parse Footer
        let file_meta = file3.metadata().await.unwrap();

        let footer_prediction = if file_meta.len() < 65536 * 2 {
            file_meta.len() // 131072 always fits in i64 ...
        } else {
            65536 * 2
        };

        // Read footer bytes in FooterParser
        file3
            .seek(SeekFrom::End(-(footer_prediction as i64)))
            .await
            .unwrap();
        let buf = &mut vec![0; footer_prediction as usize]; // Has to be vec as length is defined by dynamic value
        file3.read_exact(buf).await.unwrap();

        let mut parser = FooterParser::new(buf).unwrap();
        parser = parser.add_recipient(&privkey);
        parser = parser.parse().unwrap();

        // Check if bytes are missing
        let mut missing_buf;
        if let FooterParserState::Missing(missing_bytes) = parser.state {
            let needed_bytes = footer_prediction + missing_bytes as u64;
            file3
                .seek(SeekFrom::End(-(needed_bytes as i64)))
                .await
                .unwrap();
            missing_buf = vec![0; missing_bytes as usize]; // Has to be vec as length is defined by dynamic value
            file3.read_exact(&mut missing_buf).await.unwrap();

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

        let (sx2, rx2) = async_channel::bounded(10);

        let file3 = File::open("test.txt.out.pto").await.unwrap();

        let mut out_file1 = File::create("test.txt.out.pto.tar.gz").await.unwrap();

        let read_stream = tokio_util::io::ReaderStream::new(file3).map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        let mut reader = GenericStreamReadWriter::new_with_writer(read_stream, &mut out_file1)
            .add_transformer(ChaCha20Dec::new_with_fixed_list(keys).unwrap())
            .add_transformer(ZstdDec::new())
            .add_transformer(TarEnc::new());
        //.add_transformer(GzipEnc::new());
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
        let file1 = File::open("test.txt").await.unwrap();

        let file1_size = file1.metadata().await.unwrap().len();

        let stream1 = tokio_util::io::ReaderStream::new(file1);

        let mapped = stream1.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });
        let mut file3 = File::create("test.txt.out.2.pto").await.unwrap();

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

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(PithosTransformer::new())
            .add_transformer(FooterGenerator::new(None));
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();

        let mut file3 = File::open("test.txt.out.2.pto").await.unwrap();

        // Parse Footer
        let file_meta = file3.metadata().await.unwrap();

        let footer_prediction = if file_meta.len() < 65536 * 2 {
            file_meta.len() // 131072 always fits in i64 ...
        } else {
            65536 * 2
        };

        // Read footer bytes in FooterParser
        file3
            .seek(SeekFrom::End(-(footer_prediction as i64)))
            .await
            .unwrap();
        let buf = &mut vec![0; footer_prediction as usize]; // Has to be vec as length is defined by dynamic value
        file3.read_exact(buf).await.unwrap();

        let mut parser = FooterParser::new(buf).unwrap();
        parser = parser.add_recipient(&privkey);
        parser = parser.parse().unwrap();

        // Check if bytes are missing
        let mut missing_buf;
        if let FooterParserState::Missing(missing_bytes) = parser.state {
            let needed_bytes = footer_prediction + missing_bytes as u64;
            file3
                .seek(SeekFrom::End(-(needed_bytes as i64)))
                .await
                .unwrap();
            missing_buf = vec![0; missing_bytes as usize]; // Has to be vec as length is defined by dynamic value
            file3.read_exact(&mut missing_buf).await.unwrap();

            parser = parser.add_bytes(&missing_buf).unwrap();
            parser = parser.parse().unwrap()
        }

        // Parse the footer bytes and display Table of Contents
        let footer: Footer = parser.try_into().unwrap();

        let (_sx2, rx2) = async_channel::bounded(10);

        let file3 = File::open("test.txt.out.2.pto").await.unwrap();

        let mut out_file1 = File::create("test.txt.out.3.pto").await.unwrap();

        let read_stream = tokio_util::io::ReaderStream::new(file3).map_err(|_| {
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

        let mut reader = GenericStreamReadWriter::new_with_writer(read_stream, &mut out_file1)
            .add_transformer(FooterUpdater::new(vec![pubkey_2], footer));
        reader.add_message_receiver(rx2).await.unwrap();
        reader.process().await.unwrap();

        let mut file3 = File::open("test.txt.out.3.pto").await.unwrap();

        // Parse Footer
        let file_meta = file3.metadata().await.unwrap();

        let footer_prediction = if file_meta.len() < 65536 * 2 {
            file_meta.len() // 131072 always fits in i64 ...
        } else {
            65536 * 2
        };

        // Read footer bytes in FooterParser
        file3
            .seek(SeekFrom::End(-(footer_prediction as i64)))
            .await
            .unwrap();
        let buf = &mut vec![0; footer_prediction as usize]; // Has to be vec as length is defined by dynamic value
        file3.read_exact(buf).await.unwrap();

        let mut parser = FooterParser::new(buf).unwrap();
        parser = parser.add_recipient(&privkey_2);
        parser = parser.parse().unwrap();

        let footer: Footer = parser.try_into().unwrap();

        assert!(footer.encryption_keys.unwrap().keys.len() > 0)
    }

    #[tokio::test]
    async fn e2e_pithos_extractor() {
        let file1 = File::open("test.txt").await.unwrap();

        let file1_size = file1.metadata().await.unwrap().len();

        let stream1 = tokio_util::io::ReaderStream::new(file1);

        let mapped = stream1.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });
        let mut file3 = File::create("test.txt.out.4.pto").await.unwrap();

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

        // Create a new GenericStreamReadWriter
        let mut aswr = GenericStreamReadWriter::new_with_writer(mapped, &mut file3)
            .add_transformer(PithosTransformer::new())
            .add_transformer(FooterGenerator::new(None));
        aswr.add_message_receiver(rx).await.unwrap();
        aswr.process().await.unwrap();

        let mut file3 = File::open("test.txt.out.4.pto").await.unwrap();

        // Parse Footer
        let file_meta = file3.metadata().await.unwrap();

        let footer_prediction = if file_meta.len() < 65536 * 2 {
            file_meta.len() // 131072 always fits in i64 ...
        } else {
            65536 * 2
        };

        // Read footer bytes in FooterParser
        file3
            .seek(SeekFrom::End(-(footer_prediction as i64)))
            .await
            .unwrap();
        let buf = &mut vec![0; footer_prediction as usize]; // Has to be vec as length is defined by dynamic value
        file3.read_exact(buf).await.unwrap();

        let mut parser = FooterParser::new(buf).unwrap();
        parser = parser.add_recipient(&privkey);
        parser = parser.parse().unwrap();

        // Parse the footer bytes and display Table of Contents
        let footer: Footer = parser.try_into().unwrap();

        let file3 = File::open("test.txt.out.4.pto").await.unwrap();

        let mut vec = Vec::new();

        let stream1 = tokio_util::io::ReaderStream::new(file3);

        let mapped = stream1.map_err(|_| {
            Box::<(dyn std::error::Error + Send + Sync + 'static)>::from("a_str_error")
        });

        let (extractor, rcv) = FooterExtractor::new(Some(privkey));

        GenericStreamReadWriter::new_with_writer(mapped, &mut vec)
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
    async fn e2e_test_resilient_parts_decryptor() {
        let file = File::open("test.txt").await.unwrap();
        let file2 = vec![];

        let repeated: Vec<u64> = vec![50860];

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
            .add_transformer(ChaChaResilient::new_with_lengths(
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
}
