use smallvec::SmallVec;

use crate::{channel::{Channel, RecvDocData}, protocol::*, session::{ChannelState, DocMem, OpenChannel, RecvDoc, RecvDocState, RecvError, ReplyState, Route, Session}, varint::*};





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

    fn recv_seg(&self, variant: u8, packet: &mut [u8], i: &mut usize) -> Result<(), RecvError> {
        let has_special_parent = variant & VARIANT_SEG_FLAG_HAS_SPECIAL_PARENT > 0;
        let has_doc_len = variant & VARIANT_SEG_FLAG_HAS_DOC_LEN > 0;
        let is_single_seg = variant & VARIANT_SEG_FLAG_IS_SINGLE_SEG > 0;
        let is_first_segment = variant & VARIANT_SEG_FLAG_IS_FIRST > 0;
        // TODO: handle closing on segments.
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
            parent_no = Some(varu64_try_read(packet, i).ok_or(RecvError::Invalid)?);
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

        if (doc_no & 1 > 0) == self.is_initiator {
            // Document number is sending. Segments cannot be received on sending docs.
            return Err(RecvError::Invalid)
        }
        // We need to handle any remaining wakers on any channel we closed, after we drop the lock.
        // This must be dropped after `entry` to prevent deadlock.
        // TODO: test drop ordering to be sure that this will drop correctly.
        let mut closed_channel = None;
        let mut recv_flushers = None;

        // Document number is receiving.
        let recv_idx = ((doc_no >> 1) % self.recv_table.len() as u64) as usize;
        let slot = &self.recv_table[recv_idx];
        let mut entry = slot.lock.lock().unwrap();

        if entry.doc_no == doc_no {
            // We handle channel closure right away, semi-independent of doc handling. It is valid
            // for a sender to close a doc by sending some segment with the close flag set.
            if is_closed && let ChannelState::Open(channel) = std::mem::take(&mut entry.channel) {
                closed_channel = Some(channel);
            }

            while let RecvDocState::ActiveReserved = &entry.doc {
                entry = slot.condvar.wait(entry).unwrap();
            }
            let RecvDocState::Active(doc) = &mut entry.doc else {
                // This must be a delayed packet, ignore it.
                // TODO: tracing & metrics.
                return Ok(());
            };

            // NOTE: we do not validate `doc_len` or `parent_no`. The values on
            // the first recv segment are considered authoritative.
            if !self.recv_doc(doc, seg_off, seg)? {
                // The doc is not complete so there is nothing to do.
                // TODO: tracing & metrics.
                return Ok(());
            }

            let Some(parent_no) = doc.parent_no else {
                // A completed doc must always have a parent.
                // The first segment (`off == 0`) must contain it.
                todo!("abandon");
            };

            // The document is completed and needs to be finished now.
            let doc_state = std::mem::replace(&mut entry.doc, RecvDocState::Finishing(Default::default()));
            // The mutex is held so this state cannot change.
            let RecvDocState::Active(doc) = doc_state else {
                unreachable!();
            };

            if let ChannelState::Open(channel) = &mut entry.channel {
                // The ref count has been incremented, we have to be careful to not leak it.
                channel.ref_count += 1;
            }
            let is_closed = entry.channel.is_closed();
            drop(entry);
            let new_channel = Channel::new(self, doc_no, doc.has_special_parent, is_closed);

            // TODO: handle waker.
            let mut waker = None;
            let mut post_to_channel = |channel: &mut OpenChannel<R>, mem: DocMem, new_channel: Channel<R>| {
                match mem {
                    DocMem::Simple(buf) => {
                        let buf = unsafe {
                            buf.assume_init()
                        };
                        channel.ready_docs.push(RecvDocData::Doc(buf, new_channel));
                        waker = channel.ready_wakers.pop();
                    }
                    DocMem::ReplyBuf(_) => {
                        let pre_state = std::mem::replace(&mut channel.reply_buffer, ReplyState::Recv(doc.total_recv, new_channel));
                        if let ReplyState::Awaiting(_, w) = pre_state {
                            waker = Some(w);
                        } else {
                            // Since we `take` the pointer range when creating this `ReplyBuf`
                            // this `ReplyBuf` must be unique and no other thread will be able
                            // to change the reply state.
                            debug_assert!(false, "unreachable");
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
                    && let ChannelState::Open(channel) = &mut entry.channel
                {
                    post_to_channel(channel, doc.mem, new_channel);
                } else if entry.doc_no > parent_no {
                    // Assuming that the sender is well-behaved and this doc has an existing parent,
                    // that parent must have been finished and closed, since this slot has a doc no
                    // greater than `parent_no`. So we need to notify the sender that this doc is
                    // finished but its parent was closed.
                    // self.schedule_send_control(VARIANT_CONTROL_FIN_PARENT_CLOSED, doc_no);
                    todo!()
                } else {
                    // `parent_no` is ahead of the latest doc no in this slot, so there cannot
                    // exist a doc with a doc no equal to `parent_no`. This is not allowed, all docs
                    // must have existing parents.
                    todo!("abandon");
                }
            } else {
                // Document number is receiving.
                let recv_idx = ((parent_no >> 1) % self.recv_table.len() as u64) as usize;
                let mut entry = self.recv_table[recv_idx].lock.lock().unwrap();
                if entry.doc_no == parent_no
                    && let ChannelState::Open(channel) = &mut entry.channel
                {
                    post_to_channel(channel, doc.mem, new_channel);
                } else if entry.doc_no > parent_no {
                    // Assuming that the sender is well-behaved and this doc has an existing parent,
                    // that parent must have been finished and closed, since this slot has a doc no
                    // greater than `parent_no`. So we need to notify the sender that this doc is
                    // finished but its parent was closed.
                    // self.schedule_send_control(VARIANT_CONTROL_FIN_PARENT_CLOSED, doc_no);
                    todo!()
                } else if entry.doc.slot_is_free() && entry.orphans_expected_parent_no.is_none_or(|p| p == parent_no) {
                    // The specified parent may not have arrived yet. We assume that the sender
                    // is well-behaved, and thus the parent must not have arrived yet. So
                    // this doc is temporarily an orphan while we wait for its parent to arrive.
                    let DocMem::Simple(doc) = doc.mem else {
                        // `mem` cannot have a different state because it is only set to a different
                        // state if it has an already received parent.
                        unreachable!()
                    };
                    let doc = unsafe {
                        doc.assume_init()
                    };
                    entry.orphans_expected_parent_no = Some(parent_no);
                    entry.adoptable_orphans.push(RecvDocData::Doc(doc, new_channel));
                } else {
                    // `parent_no` is ahead of the latest doc no in this slot and we are certain
                    // that it cannot be an orphan. So there cannot exist a doc with a doc no equal
                    // to `parent_no`. This is not allowed, all docs must have existing parents.
                    todo!("abandon");
                }
            }
        } else if entry.doc_no < doc_no {
            // TODO: lockless single-segment document handling.
            let Some(doc_len) = doc_len else {
                // If first recv seg of a doc does not specify the document length then
                // it is ignored.
                return Ok(());
            };

            if !entry.doc.slot_is_free() {
                // The sender must not use the recv slot of a document that is not finished or has
                // an open channel. They must wait for us to send a fin control frame first.
                todo!("abandon");
            }

            // The sender is responsible for managing our recv slots. When a new doc populates a
            // recv slot, this is implicitly treated as us receiving a `fin-ack` and a `close` for
            // the previous doc in this recv slot.
            entry.doc_no = doc_no;
            entry.needs_send_control = false;

            // Mark this recv slot as `ActiveReserved` and process its state as if a `fin-ack` was
            // recv for the previous doc.
            if let RecvDocState::Finishing(flushers) = std::mem::replace(&mut entry.doc, RecvDocState::ActiveReserved) {
                recv_flushers = Some(flushers);
            }

            if entry.orphans_expected_parent_no.is_some_and(|p| p != doc_no) {
                // If this recv slot has adoptable orphans, then the next doc to use this slot
                // must be their parent.
                todo!("abandon");
            }
            // Adopt any existing orphans.
            let mut ready_docs = SmallVec::new();
            std::mem::swap(&mut ready_docs, &mut entry.adoptable_orphans);

            // Mark this recv slot as `Open` and process its state as if a `close` was recv for the
            // previous doc.
            let new_channel_state = ChannelState::Open(OpenChannel {
                ref_count: 0,
                ready_wakers: SmallVec::new(),
                ready_docs,
                reply_buffer: Default::default(),
            });
            if let ChannelState::Open(channel) = std::mem::replace(&mut entry.channel, new_channel_state) {
                closed_channel = Some(channel);
            }

            // This doc slot is fully initialized and can be safely replaced with the
            // new doc.
            let mut mem = None;
            let mut needs_notify = false;
            if has_special_parent && let Some(parent_no) = parent_no {
                // If this doc has a special parent we must look up that parent before allocating the doc.
                if parent_no >= doc_no {
                    // Parent docs must be older than child docs.
                    return Err(RecvError::Invalid);
                }
                needs_notify = true;
                // We must drop the lock to prevent deadlock when looking up a document's parent.
                drop(entry);

                // We cannot hold two locks into the send/recv tables at the same time.
                // This is why we set the `RecvDocState` to reserved, so we can unlock.
                let mut has_open_parent = false;
                self.update_channel(parent_no, |channel| {
                    has_open_parent = true;
                    mem = channel.reply_buffer.try_incoming().map(DocMem::ReplyBuf)
                });

                entry = slot.lock.lock().unwrap();
            }
            debug_assert!(matches!(&entry.doc, RecvDocState::ActiveReserved));

            let mut doc = RecvDoc {
                mem: mem.unwrap_or_else(|| DocMem::Simple(Box::new_uninit_slice(doc_len))),
                total_recv: 0,
                set_segs: vec![0; doc_len.div_ceil(usize::BITS as usize)],
                has_special_parent,
                parent_no,
            };
            if self.recv_doc(&mut doc, seg_off, seg)? {
                todo!();
            }

            entry.doc = RecvDocState::Active(doc);
            drop(entry);

            // Now that the lock is dropped we can send notifications to any waiting threads/tasks.
            if needs_notify {
                slot.condvar.notify_all();
            }
        }
        Ok(())
    }

    pub(crate) fn recv(&self, packet: &mut [u8], route: R) -> Result<(), RecvError> {
        // TODO: Decrypt packet.

        let mut ack_eliciting = false;
        let mut i = 0;
        while i < packet.len() {
            let variant = packet[i];
            i += 1;
            match variant {
                VARIANT_NULL_TERMINATOR => break,
                VARIANT_SEG_MIN..=VARIANT_SEG_MAX => {
                    ack_eliciting = true;
                    self.recv_seg(variant, packet, &mut i)?;
                }
                VARIANT_ACK_SINGLE | VARIANT_ACK_RUN => {}
                VARIANT_PADDING => {}
                _ => return Err(RecvError::Invalid),
            }
        }
        Ok(())
    }
}
