use crate::helpers::notifications::{Message, Notifier};
use crate::transformer::{Sink, Transformer, TransformerType};
use anyhow::{anyhow, Result};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::Bytes;
use hyper::body::Body;
use std::sync::Arc;
use tracing::{debug, error};

pub struct PithosBody {
    receiver: Receiver<Bytes>,
}

impl PithosBody {
    pub fn channel() -> (Sender<Bytes>, Self) {
        let (sender, receiver) = async_channel::bounded(1000);
        (sender, Self { receiver })
    }
}

impl Body for PithosBody {
    type Data = Bytes;
    type Error = anyhow::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        match self.receiver.try_recv() {
            Ok(data) => std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(data)))),
            Err(TryRecvError::Empty) => std::task::Poll::Pending,
            Err(TryRecvError::Closed) => std::task::Poll::Ready(None),
        }
    }
}

pub struct HyperSink {
    sender: Sender<Bytes>,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
}

impl Sink for HyperSink {}

impl HyperSink {
    #[tracing::instrument(level = "trace", skip())]
    pub fn new() -> (Self, PithosBody) {
        let (sender, body) = PithosBody::channel();
        (
            Self {
                sender,
                notifier: None,
                msg_receiver: None,
                idx: None,
            },
            body,
        )
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<()> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => {
                        if let Some(notifier) = &self.notifier {
                            notifier.send_read_writer(Message::Finished)?;
                        }
                        debug!("finished");
                        break;
                    }
                    Ok(_) => {}
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Closed) => {
                        error!("Message receiver closed");
                        return Err(anyhow!("Message receiver closed"));
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Transformer for HyperSink {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::HyperSink, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        self.sender.send(buf.split().freeze()).await?;
        if buf.is_empty() {
            self.process_messages()?;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}
