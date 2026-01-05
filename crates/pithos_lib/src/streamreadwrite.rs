use crate::helpers::notifications::{Message, Notifier};
use crate::helpers::structs::FileContext;
use crate::transformer::{ReadWriter, Sink, Transformer};
use crate::transformers::writer_sink::WriterSink;
use anyhow::{anyhow, bail, Result};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use std::collections::VecDeque;
use std::mem;
use std::sync::Arc;
use tokio::io::{AsyncWrite, BufWriter};
use tracing::error;

pub struct GenericStreamReadWriter<
    'a,
    R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
        + Unpin
        + Send
        + Sync,
> {
    input_stream: R,
    notifier: Option<Arc<Notifier>>,
    transformers: Vec<Box<dyn Transformer + Send + Sync + 'a>>,
    sink: Option<Box<dyn Transformer + Send + Sync + 'a>>,
    context_queue: VecDeque<FileContext>,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    size_counter: usize,
    external_receiver: Option<Receiver<Message>>,
    file_counter: usize,
    dir_counter: usize,
}

impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > GenericStreamReadWriter<'a, R>
{
    #[tracing::instrument(level = "trace", skip(input_stream, transformer))]
    pub fn new_with_sink<T: Transformer + Sink + Send + Sync + 'a>(
        input_stream: R,
        transformer: T,
    ) -> Self {
        let (sx, rx) = async_channel::unbounded();
        GenericStreamReadWriter {
            input_stream,
            notifier: None,
            sink: Some(Box::new(transformer)),
            transformers: Vec::new(),
            context_queue: VecDeque::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            external_receiver: None,
            file_counter: 0,
            dir_counter: 0,
        }
    }

    #[tracing::instrument(level = "trace", skip(input_stream, writer))]
    pub fn new_with_writer<W: AsyncWrite + Send + Sync + 'a>(input_stream: R, writer: W) -> Self {
        let (sx, rx) = async_channel::unbounded();
        GenericStreamReadWriter {
            input_stream,
            notifier: None,
            sink: Some(Box::new(WriterSink::new(BufWriter::new(Box::pin(writer))))),
            transformers: Vec::new(),
            context_queue: VecDeque::new(),
            sender: sx,
            receiver: rx,
            size_counter: 0,
            external_receiver: None,
            file_counter: 0,
            dir_counter: 0,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, transformer))]
    pub fn add_transformer<T: Transformer + Send + Sync + 'a>(mut self, transformer: T) -> Self {
        self.transformers.push(Box::new(transformer));
        self
    }

    #[tracing::instrument(level = "trace", skip(self, file_ctx))]
    pub async fn set_file_ctx(&mut self, mut file_ctx: FileContext) {
        if file_ctx.is_dir {
            file_ctx.idx = self.dir_counter;
            self.dir_counter += 1;
        } else if file_ctx.symlink_target.is_none() {
            file_ctx.idx = self.file_counter;
            self.file_counter += 1;
        }
        self.context_queue.push_back(file_ctx)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn process_messages(&mut self) -> Result<bool> {
        while let Some(rx) = &self.external_receiver {
            if self.context_queue.is_empty() {
                match rx.try_recv() {
                    Ok(Message::Completed) => {
                        return Ok(true);
                    }
                    Ok(Message::FileContext(context)) => {
                        let mut context = context.clone();
                        if context.is_dir {
                            context.idx = self.dir_counter;
                            self.dir_counter += 1;
                        } else if context.symlink_target.is_none() {
                            context.idx = self.file_counter;
                            self.file_counter += 1;
                        }
                        self.context_queue.push_back(context);
                    }
                    Err(TryRecvError::Empty) => break,
                    _ => {}
                }
            }

            match rx.try_recv() {
                Err(TryRecvError::Empty) => break,
                Ok(ref msg) => match &msg {
                    &Message::FileContext(context) => {
                        let mut context = context.clone();
                        if context.is_dir {
                            context.idx = self.dir_counter;
                            self.dir_counter += 1;
                        } else if context.symlink_target.is_none() {
                            context.idx = self.file_counter;
                            self.file_counter += 1;
                        }
                        self.context_queue.push_back(context);
                    }
                    Message::Completed => {
                        return Ok(true);
                    }
                    _ => {}
                },
                Err(TryRecvError::Closed) => {
                    self.external_receiver = None;
                    break;
                }
            }
        }

        loop {
            match self.receiver.try_recv() {
                Err(TryRecvError::Empty) => break,
                Ok(ref msg) => match &msg {
                    &Message::FileContext(context) => {
                        let mut context = context.clone();
                        if context.is_dir {
                            context.idx = self.dir_counter;
                            self.dir_counter += 1;
                        } else if context.symlink_target.is_none() {
                            context.idx = self.file_counter;
                            self.file_counter += 1;
                        }
                        self.context_queue.push_back(context.clone());
                    }
                    Message::Completed => {
                        return Ok(true);
                    }
                    _ => {}
                },
                Err(TryRecvError::Closed) => bail!("Channel closed!"),
            }
        }

        Ok(false)
    }
}

#[async_trait::async_trait]
impl<
        'a,
        R: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync + 'static>>>
            + Unpin
            + Send
            + Sync,
    > ReadWriter for GenericStreamReadWriter<'a, R>
{
    #[tracing::instrument(err, level = "trace", skip(self))]
    async fn process(&mut self) -> Result<()> {
        // The buffer that accumulates the "actual" data
        let mut read_buf = BytesMut::with_capacity(65_536 * 2);
        let mut hold_buffer = BytesMut::with_capacity(65536);
        let mut data;
        let mut read_bytes: usize = 0;
        let mut empty_counter: Option<u8> = Some(0);
        let mut finished = false;

        self.transformers
            .push(self.sink.take().ok_or_else(|| anyhow!("No sink!"))?);

        let notifier = Arc::new(Notifier::new(self.sender.clone()));
        self.notifier = Some(notifier.clone());
        for (idx, t) in self.transformers.iter_mut().enumerate() {
            notifier.add_transformer(t.initialize(idx).await);
            t.set_notifier(notifier.clone()).await?;
        }

        let _ = self.process_messages().await?;
        let mut file_ctx = self.context_queue.pop_front();

        if let Some(ctx) = &file_ctx {
            notifier.send_all(Message::FileContext(ctx.clone()))?;
        }

        loop {
            if hold_buffer.is_empty() && !finished {
                data = self
                    .input_stream
                    .next()
                    .await
                    .unwrap_or_else(|| Ok(Bytes::new()))
                    .unwrap_or_default();
                read_bytes = data.len();
                if read_bytes == 0 {
                    if let Some(counter) = &mut empty_counter {
                        *counter += 1;
                        if *counter > 5 {
                            notifier.send_first(Message::Finished)?;
                            empty_counter = None;
                        }
                    }
                }
                read_buf.put(data);
            } else if read_buf.is_empty() {
                // Swap hold buffer back to read buffer
                mem::swap(&mut hold_buffer, &mut read_buf);
                // If no file is available discard the remaining hold buffer bytes
                if file_ctx.is_none() {
                    hold_buffer.clear();
                    notifier.send_first(Message::Finished)?;
                    finished = true;
                }
            }

            let completed = self.process_messages().await?;

            if let Some(context) = &file_ctx {
                self.size_counter += read_bytes;
                if self.size_counter > context.compressed_size as usize {
                    let mut diff = read_buf
                        .len()
                        .saturating_sub(self.size_counter - context.compressed_size as usize);
                    if diff >= context.compressed_size as usize {
                        diff = context.compressed_size as usize
                    }
                    hold_buffer = read_buf.split_to(diff);
                    mem::swap(&mut read_buf, &mut hold_buffer);
                    self.size_counter -= context.compressed_size as usize;

                    // Fetch next file context and send to transformers if present
                    file_ctx = self.context_queue.pop_front();
                    if let Some(ctx) = &file_ctx {
                        notifier.send_all(Message::FileContext(ctx.clone()))?;
                    }
                    // Send flush
                    notifier.send_all(Message::ShouldFlush)?;
                    // Reset counter
                    self.size_counter = hold_buffer.len();
                } else if self.size_counter == context.compressed_size as usize
                    && hold_buffer.is_empty()
                {
                    // Fetch next file context and send to transformers if present
                    file_ctx = self.context_queue.pop_front();
                    if let Some(ctx) = &file_ctx {
                        notifier.send_all(Message::FileContext(ctx.clone()))?;
                    }
                    // Send flush
                    notifier.send_all(Message::ShouldFlush)?;
                    // Reset counter
                    self.size_counter = 0;
                }
            }

            for t in self.transformers.iter_mut() {
                t.process_bytes(&mut read_buf).await?;
            }

            if read_buf.is_empty() && completed {
                break;
            }
            read_bytes = 0;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, message))]
    async fn announce_all(&mut self, message: Message) -> Result<()> {
        if let Some(notifier) = &self.notifier {
            notifier.send_all(message)?;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, rx))]
    async fn add_message_receiver(&mut self, rx: Receiver<Message>) -> Result<()> {
        if self.external_receiver.is_none() {
            self.external_receiver = Some(rx);
            Ok(())
        } else {
            error!("Overwriting existing receivers is not allowed!");
            bail!("[READ_WRITER] Overwriting existing receivers is not allowed!")
        }
    }
}
