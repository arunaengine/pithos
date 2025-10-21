use crate::helpers::notifications::{Message, Notifier};
use crate::helpers::structs::Range;
use crate::transformer::{Transformer, TransformerType};
use anyhow::{anyhow, Result};
use async_channel::{Receiver, Sender, TryRecvError};
use bytes::{Buf, BufMut, BytesMut};
use std::sync::Arc;
use tracing::error;

#[derive(Debug, PartialEq, Clone, Eq, PartialOrd, Ord)]
pub enum FilterParam {
    Discard(u64),
    Keep(u64),
    DiscardAll,
    KeepAll,
}

pub struct Filter {
    param: FilterParam,
    filter: Vec<FilterParam>,
    captured_buf_len: usize,
    advanced_by: usize,
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    previous_finished: bool,
}

impl Filter {
    #[tracing::instrument(level = "trace", skip(filter))]
    #[allow(dead_code)]
    pub fn new_with_range(filter: Range) -> Self {
        Filter {
            param: FilterParam::Discard(filter.from),
            filter: vec![
                FilterParam::DiscardAll,
                FilterParam::Keep(filter.to - filter.from),
            ],
            captured_buf_len: 0,
            advanced_by: 0,
            notifier: None,
            msg_receiver: None,
            idx: None,
            previous_finished: false,
        }
    }

    #[tracing::instrument(level = "trace", skip(edit_list))]
    #[allow(dead_code)]
    pub fn from_edit_list(edit_list: Vec<u64>) -> Vec<FilterParam> {
        let mut filter: Vec<_> = edit_list
            .iter()
            .enumerate()
            .map(|(i, e)| {
                if i % 2 == 0 {
                    FilterParam::Discard(*e)
                } else {
                    FilterParam::Keep(*e)
                }
            })
            .collect();
        filter.push(FilterParam::DiscardAll);
        filter.reverse();
        filter
    }

    #[tracing::instrument(level = "trace", skip(filter))]
    #[allow(dead_code)]
    pub fn new_with_edit_list(filter: Option<Vec<u64>>) -> Self {
        let mut list = Self::from_edit_list(filter.unwrap_or_default());
        Filter {
            param: list.pop().unwrap_or(FilterParam::KeepAll),
            filter: list,
            captured_buf_len: 0,
            advanced_by: 0,
            notifier: None,
            msg_receiver: None,
            idx: None,
            previous_finished: false,
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<()> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) | Ok(Message::ShouldFlush) => {
                        self.previous_finished = true;
                        return Ok(());
                    }
                    Ok(Message::EditList(filter)) => {
                        if self.filter.is_empty() {
                            self.filter = Self::from_edit_list(filter);
                        } else {
                            error!("Edit list received, but filter already set");
                            return Err(anyhow!("Edit list received, but filter already set"));
                        }
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

    fn next_param(&mut self) {
        let next = self.filter.pop();
        self.param = next.unwrap_or(FilterParam::DiscardAll);
    }
}

#[async_trait::async_trait]
impl Transformer for Filter {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::Filter, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut BytesMut) -> Result<()> {
        self.captured_buf_len = buf.len();
        self.advanced_by = 0;

        self.process_messages()?;

        // If bytes are present in the buffer
        if !buf.is_empty() {
            let mut keep_buf = BytesMut::with_capacity(buf.len());
            loop {
                match &mut self.param {
                    FilterParam::Discard(bytes) => {
                        if buf.len() < *bytes as usize {
                            buf.clear();
                            *bytes -= buf.len() as u64;
                            break;
                        } else {
                            buf.advance(*bytes as usize);
                            self.next_param();
                        }
                    }
                    FilterParam::Keep(bytes) => {
                        if buf.len() < *bytes as usize {
                            *bytes -= buf.len() as u64;
                            if !keep_buf.is_empty() {
                                keep_buf.put(buf.split());
                            }
                            break;
                        } else {
                            keep_buf.put(buf.split_to(*bytes as usize));
                            self.next_param();
                        }
                    }
                    FilterParam::DiscardAll => {
                        buf.clear();
                        break;
                    }
                    FilterParam::KeepAll => {
                        break;
                    }
                }
            }
            if !keep_buf.is_empty() {
                buf.clear();
                buf.put(keep_buf);
            }
        } else if self.previous_finished
            && [FilterParam::DiscardAll, FilterParam::KeepAll].contains(&self.param)
        {
            if let Some(notifier) = &self.notifier {
                notifier.send_next(
                    self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                    Message::Finished,
                )?;
            }
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
