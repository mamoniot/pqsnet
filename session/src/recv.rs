use std::{
    sync::{MutexGuard, atomic::Ordering},
    task::Waker,
};

use smallvec::SmallVec;
use tracing::*;

use crate::{
    application_layer::Route, protocol::*, session::{
        DocMem, DocNo, OpenChannel, RecvDoc, RecvDocInner, RecvDocState, RecvError, ReplyState, Session,
        UnfinishedRecvDoc, UnreleasedChannel,
    }, varint::*,
};

impl<R: Route> Session<R> {
    /// This function returns `true` only if the document has been fully populated by recv segs.
    fn recv_doc(&self, doc: &mut RecvDoc, seg_off: usize, seg: &[u8]) -> Result<bool, RecvError> {
        // TODO: handle length mismatches for reply buffers.
        fn check_overlap(set_seg: &mut usize, set_bits: usize) -> usize {
            let pre_bits = *set_seg;
            *set_seg |= set_bits;

            let bits_set = !pre_bits & set_bits;
            bits_set.count_ones() as usize
        }

        let doc_len = doc.mem.len();

        if seg.is_empty() {
            return Ok(doc_len == 0);
        }
        let seg_end = seg_off + seg.len() - 1;
        if seg_end >= doc_len {
            return Err(RecvError::Invalid);
        }
        let seg_off_idx = seg_off / usize::BITS as usize;
        let seg_off_rem = seg_off % usize::BITS as usize;
        let seg_end_idx = seg_end / usize::BITS as usize;
        let seg_end_rem = seg_end % usize::BITS as usize;

        let seg_off_set = usize::MAX >> seg_off_rem;
        let seg_end_set = usize::MAX << (usize::BITS as usize - seg_end_rem - 1);

        let mut total_new_bytes = 0;
        if seg_off_idx == seg_end_idx {
            total_new_bytes += check_overlap(&mut doc.set_segs[seg_off_idx], seg_off_set & seg_end_set);
        } else {
            total_new_bytes += check_overlap(&mut doc.set_segs[seg_off_idx], seg_off_set);
            for i in seg_off_idx + 1..seg_end_idx - 1 {
                total_new_bytes += check_overlap(&mut doc.set_segs[i], usize::MAX);
            }
            total_new_bytes += check_overlap(&mut doc.set_segs[seg_end_idx], seg_end_set);
        }

        doc.total_recv += total_new_bytes;
        doc.mem.write(seg_off, seg);
        Ok(doc.total_recv == doc_len)
    }

    /// It is the caller's responsibility to guarantee that every portion of the document
    /// has been written to by all of the sender's segments.
    fn fin_doc(&self, doc_no: DocNo, mut entry: MutexGuard<RecvDocInner>) -> Result<(), RecvError> {
        // The document is completed and needs to be finished now.
        let doc_state = std::mem::replace(&mut entry.doc, RecvDocState::Finishing(Default::default()));
        // The mutex is held so this state cannot change.
        let RecvDocState::Active(doc) = doc_state else {
            unreachable!();
        };

        let Some(parent_no) = doc.parent_no else {
            // A completed doc must always have a parent.
            // The first segment (`off == 0`) must contain it.
            return Err(RecvError::Invalid);
        };

        if let Some(channel) = &mut entry.channel {
            // The ref count has been incremented, we have to be careful to not leak it.
            channel.ref_count += 1;
        }
        let is_closed = entry.channel.is_none();
        drop(entry);

        // Past this point this function needs to guarantee that something takes ownership of this
        // doc, that this doc is fin-closed or that the session is abandoned.

        // This function causes the given channel to take ownership of this unfinished doc.
        let post_to_channel = |channel: &mut OpenChannel, mem: DocMem| -> Option<Waker> {
            match mem {
                DocMem::Simple(buf) => {
                    // It is the caller's responsibility to guarantee that every portion of the
                    // document has been written to by all of the sender's segments.
                    let buf = unsafe { buf.assume_init() };
                    channel.ready_docs.push(UnfinishedRecvDoc {
                        buf,
                        doc_no,
                        has_special_parent: doc.has_special_parent,
                        is_closed,
                    });
                    channel.ready_wakers.pop()
                }
                DocMem::ReplyBuf(_) => {
                    let new_state = ReplyState::Recv(
                        doc.total_recv,
                        UnreleasedChannel {
                            doc_no,
                            has_special_parent: doc.has_special_parent,
                            is_closed,
                        },
                    );
                    if let ReplyState::Awaiting(_, w) = std::mem::replace(&mut channel.reply_buffer, new_state) {
                        Some(w)
                    } else {
                        // Since we `take` the pointer range when creating this `ReplyBuf`
                        // this `ReplyBuf` must be unique and no other thread will be able
                        // to change the reply state.
                        unreachable!();
                    }
                }
            }
        };

        // Get the doc's parent to find the recv channel.
        if (parent_no & 1 > 0) == self.is_initiator {
            // Document number is sending.
            let send_idx = ((parent_no >> 1) % self.send_table.len() as u64) as usize;
            let mut entry = self.send_table[send_idx].lock.lock().unwrap();
            if entry.doc_no == parent_no
                && let Some(channel) = &mut entry.channel
            {
                let waker = post_to_channel(channel, doc.mem);
                drop(entry);
                if let Some(waker) = waker {
                    waker.wake();
                }
                Ok(())
            } else if entry.doc_no >= parent_no {
                // Assuming that the sender is well-behaved and this doc has an existing parent,
                // that parent must have been finished and closed, since this slot has a doc no
                // greater than `parent_no`. So we need to notify the sender that this doc is
                // finished but its parent was closed.
                // TODO: provide a more reliable source of the doc len.
                self.drop_unfinished_recv_doc(doc_no, doc.total_recv);
                Ok(())
            } else {
                // `parent_no` is ahead of the latest doc no in this slot, so there cannot
                // exist a doc with a doc no equal to `parent_no`. This is not allowed, all docs
                // must have existing parents.
                Err(RecvError::Invalid)
            }
        } else {
            // Document number is receiving.
            let recv_idx = ((parent_no >> 1) % self.recv_table.len() as u64) as usize;
            let mut entry = self.recv_table[recv_idx].lock.lock().unwrap();
            if entry.doc_no == parent_no
                && let Some(channel) = &mut entry.channel
            {
                let waker = post_to_channel(channel, doc.mem);
                drop(entry);
                if let Some(waker) = waker {
                    waker.wake();
                }
                Ok(())
            } else if entry.doc_no >= parent_no {
                // Assuming that the sender is well-behaved and this doc has an existing parent,
                // that parent must have been finished and closed, since this slot has a doc no
                // greater than `parent_no`. So we need to notify the sender that this doc is
                // finished but its parent was closed.
                self.drop_unfinished_recv_doc(doc_no, doc.total_recv);
                Ok(())
            } else if entry.doc.slot_is_fin() && entry.orphans_expected_parent_no.is_none_or(|p| p == parent_no) {
                // The specified parent may not have arrived yet. We assume that the sender
                // is well-behaved, and thus the parent must not have arrived yet. So
                // this doc is temporarily an orphan while we wait for its parent to arrive.
                let DocMem::Simple(buf) = doc.mem else {
                    // `mem` cannot have a different state because it is only set to a different
                    // state if it has an already received parent.
                    unreachable!()
                };
                // It is the caller's responsibility to guarantee that every portion of the document
                // has been written to by all of the sender's segments.
                let buf = unsafe { buf.assume_init() };
                entry.orphans_expected_parent_no = Some(parent_no);
                entry.adoptable_orphans.push(UnfinishedRecvDoc {
                    buf,
                    doc_no,
                    has_special_parent: doc.has_special_parent,
                    is_closed,
                });
                Ok(())
            } else {
                // `parent_no` is ahead of the latest doc no in this slot and we are certain
                // that it cannot be an orphan. So there cannot exist a doc with a doc no equal
                // to `parent_no`. This is not allowed, all docs must have existing parents.
                Err(RecvError::Invalid)
            }
        }
    }

    /// If this returns `RecvError::Invalid`, the caller is expected to abandon this session.
    fn recv_seg(&self, variant: u8, packet: &mut [u8], i: &mut usize) -> Result<(), RecvError> {
        /* SEGMENT PARSING */

        let has_special_parent = variant & VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT > 0;
        let has_doc_len = variant & VARIANT_SEG_FLAG_HAS_DOC_LEN > 0;
        let is_single_seg = variant & VARIANT_SEG_FLAG_IS_SINGLE_SEG > 0;
        let is_first_segment = variant & VARIANT_SEG_FLAG_IS_FIRST > 0;
        let is_closed = variant & VARIANT_SEG_FLAG_IS_CLOSED > 0;
        let variant_len = variant & VARIANT_SEG_LEN_MASK;
        let mut doc_len = None;
        let mut parent_no = None;
        let mut seg_off = 0;

        let doc_no = varu64_try_read(packet, i).ok_or(RecvError::Invalid)?;
        if has_doc_len {
            doc_len = Some(varusize_try_read(packet, i).ok_or(RecvError::Invalid)?);
        }
        if has_special_parent || is_first_segment {
            let p = varu64_try_read(packet, i).ok_or(RecvError::Invalid)?;
            // NOTE: This is one of the only places that asserts that doc numbers must increase.
            // Parent docs must be older than child docs. Older docs have smaller doc numbers.
            if p >= doc_no {
                return Err(RecvError::Invalid);
            }
            parent_no = Some(p);
        }
        if !is_first_segment {
            seg_off = varusize_try_read(packet, i).ok_or(RecvError::Invalid)?;
        }

        let seg = if variant_len == VARIANT_SEG_IS_TERMINATOR {
            let ret = &packet[*i..];
            *i = packet.len();
            ret
        } else if variant_len == VARIANT_SEG_HAS_LEN {
            let seg_len = varusize_try_read(packet, i).ok_or(RecvError::Invalid)?;
            let seg_start = *i;
            *i = i.saturating_add(seg_len);
            packet.get(seg_start..*i).ok_or(RecvError::Invalid)?
        } else {
            debug_assert_eq!(variant_len, VARIANT_SEG_HAS_TERMINATOR);
            let seg_start = *i;
            *i = packet.len();
            let mut seg_end = packet.len() - 1;
            loop {
                if seg_start > seg_end {
                    return Err(RecvError::Invalid);
                }
                if packet[seg_end] == VARIANT_NULL_TERMINATOR {
                    break;
                }
                seg_end -= 1;
            }
            &packet[seg_start..seg_end]
        };

        if is_single_seg {
            doc_len.get_or_insert(seg.len());
        }

        /* DOCUMENT LOOKUP */

        if (doc_no & 1 > 0) == self.is_initiator {
            // Document number is sending. Segments cannot be received on sending docs.
            return Err(RecvError::Invalid);
        }

        // Document number is receiving.
        let recv_idx = ((doc_no >> 1) % self.recv_table.len() as u64) as usize;
        let slot = &self.recv_table[recv_idx];
        let mut entry = slot.lock.lock().unwrap();

        if entry.doc_no == doc_no {
            /* DOCUMENT UPDATE */

            // We handle channel closure right away, semi-independent of doc handling. It is valid
            // for a sender to close a doc by sending some segment with the close flag set.
            // `OpenChannel` structs have ownership of resources that need explicit dropping.
            // Past this point this function must not return without handling `closed_channel`.
            let closed_channel = if is_closed {entry.channel.take()} else {None};

            while let RecvDocState::ActiveReserved = &entry.doc {
                entry = slot.condvar.wait(entry).unwrap();
            }
            let RecvDocState::Active(doc) = &mut entry.doc else {
                // This must be a delayed packet, ignore it.
                // TODO: tracing & metrics.
                drop(entry);
                self.drop_closed_channel(closed_channel);
                return Ok(());
            };

            // We do not validate `doc_len` or `parent_no`. The values on
            // the first recv segment are considered authoritative.
            let ret = match self.recv_doc(doc, seg_off, seg) {
                Ok(false) => {
                    drop(entry);
                    Ok(())
                }
                Ok(true) => self.fin_doc(doc_no, entry),
                Err(e) => {
                    drop(entry);
                    Err(e)
                }
            };

            self.drop_closed_channel(closed_channel);
            ret
        } else if entry.doc_no < doc_no {
            /* DOCUMENT CREATION */
            // This is the only place that populates a send slot.

            let Some(doc_len) = doc_len else {
                // If first recv seg of a doc does not specify the document length then
                // it is ignored.
                return Ok(());
            };

            if !entry.doc.slot_is_fin() {
                // The sender must not use the recv slot of a document that is not finished or has
                // an open channel. They must wait for us to send a fin control frame first.
                return Err(RecvError::Invalid);
            }

            if entry.orphans_expected_parent_no.is_some_and(|p| p != doc_no) {
                // If this recv slot has adoptable orphans, then the next doc to use this slot
                // must be their parent.
                return Err(RecvError::Invalid);
            }

            // TODO: prove that this load cannot be reordered before an increase.
            let recv_bytes_max = self.recv_bytes_max.load(Ordering::SeqCst);
            let res = self
                .recv_bytes_total
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |b| {
                    // With a well-behaved peer this update never fails. The ABA problem is not an
                    // error condition for this increment.
                    let next_total = b.checked_add(doc_len)?;
                    (next_total <= recv_bytes_max).then_some(next_total)
                });
            if res.is_err() {
                // The sender is attempting to go above our recv bytes limit. The sender
                // always know a value for our recv bytes limit that is less than the current value,
                // so this can only happen if the sender is misbehaving.
                return Err(RecvError::Invalid);
            }
            // Past this point, we assume that either the doc is being accepted or the session will
            // be abandoned. If this assumption holds it means we cannot leak the increment we just
            // made to `recv_bytes_total`

            // The sender is responsible for managing our recv slots. When a new doc populates a
            // recv slot, this is implicitly treated as us receiving a `fin-ack` and a `close` for
            // the previous doc in this recv slot.
            entry.doc_no = doc_no;
            entry.needs_send_control = false;

            // Mark this recv slot as `ActiveReserved` and process its state as if a `fin-ack` was
            // recv for the previous doc.
            // `recv_flushers` has a drop methods that will guarantee its wakers will be awoken,
            // but we will explicitly drop them anyways for the sake of clarity.
            let mut recv_flushers = None;
            if let RecvDocState::Finishing(flushers) = std::mem::replace(&mut entry.doc, RecvDocState::ActiveReserved) {
                recv_flushers = Some(flushers);
            }

            // Adopt any existing orphans. `orphans_expected_parent_no` was checked above.
            let mut ready_docs = SmallVec::new();
            std::mem::swap(&mut ready_docs, &mut entry.adoptable_orphans);

            // Something must take ownership of the orphan docs or they must be closed.
            // Past this point this function must not return without handling `closed_orphans`.
            let mut closed_orphans = SmallVec::new();
            // `OpenChannel` structs have ownership of resources that need explicit dropping.
            // Past this point this function must not return without handling `closed_channel`.
            let closed_channel;
            if is_closed {
                closed_orphans = ready_docs;
                closed_channel = entry.channel.take();
            } else {
                closed_channel = entry.channel.replace(OpenChannel {
                    ref_count: 0,
                    ready_wakers: SmallVec::new(),
                    ready_docs,
                    reply_buffer: Default::default(),
                })
            };

            // If this doc has a special parent we must look it up before allocating the doc.
            let mut mem = None;
            // From this point on we cannot return without explicitly handling `needs_notify`.
            let mut needs_notify = false;
            if has_special_parent && let Some(parent_no) = parent_no {
                needs_notify = true;
                // We must drop the lock to prevent deadlock when looking up a document's parent.
                // We cannot hold two locks into the send/recv tables at the same time.
                // This is why we set the `RecvDocState` to reserved, so we can unlock.
                drop(entry);

                let mut has_open_parent = false;
                self.update_channel(parent_no, |channel| {
                    has_open_parent = true;
                    mem = channel.reply_buffer.try_incoming().map(DocMem::ReplyBuf)
                });

                entry = slot.lock.lock().unwrap();
            }
            debug_assert!(matches!(&entry.doc, RecvDocState::ActiveReserved));

            // This doc slot is fully initialized and can be safely replaced with the new doc.
            // OPTIMIZATION: If this doc is a single segment, we do not need to track `set_segs` or
            // `total_recv`. Eliminate them in that case.
            let mut doc = RecvDoc {
                mem: mem.unwrap_or_else(|| DocMem::Simple(Box::new_uninit_slice(doc_len))),
                total_recv: 0,
                set_segs: vec![0; doc_len.div_ceil(usize::BITS as usize)],
                has_special_parent,
                parent_no,
            };

            let ret = match self.recv_doc(&mut doc, seg_off, seg) {
                Ok(false) => {
                    entry.doc = RecvDocState::Active(doc);
                    drop(entry);
                    Ok(())
                }
                Ok(true) => {
                    // `fin_doc` expects `entry.doc == RecvDocState::Active(..)`
                    entry.doc = RecvDocState::Active(doc);
                    self.fin_doc(doc_no, entry)
                }
                Err(e) => {
                    drop(entry);
                    Err(e)
                }
            };

            if needs_notify {
                slot.condvar.notify_all();
            }
            drop(recv_flushers);
            for orphan in closed_orphans {
                self.drop_unfinished_recv_doc(orphan.doc_no, orphan.buf.len());
            }
            self.drop_closed_channel(closed_channel);
            ret
        } else {
            // This must be a delayed packet, ignore it.
            // TODO: tracing & metrics.
            Ok(())
        }
    }

    pub(crate) fn recv(&self, packet: &mut [u8], i: &mut usize, route: R) {
        // TODO: Decrypt packet.``

        let mut ack_eliciting = false;
        while *i < packet.len() {
            let variant = packet[*i];
            *i += 1;
            match variant {
                VARIANT_NULL_TERMINATOR => break,
                VARIANT_SEG_MIN..=VARIANT_SEG_MAX => {
                    ack_eliciting = true;
                    let ret = self.recv_seg(variant, packet, i);
                    if ret.is_err() {
                        self.abandon();
                        return;
                    }
                }
                VARIANT_ACK_SINGLE | VARIANT_ACK_RUN => {}
                VARIANT_PADDING => {}
                _ => {
                    warn!("received unrecognized frame variant '{variant}'");
                }
            }
        }
    }
}
