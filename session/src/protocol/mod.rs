/* PAYLOAD FRAME VARIANTS */

pub const VARIANT_NULL_TERMINATOR: u8 = 0x0;
pub const VARIANT_PADDING: u8 = 0xFF;

/// Segment Frame {
/// Segment length type (2),
/// Segment has offset flag (1),
/// Segment has metadata flag (1),
/// Segment has custom memory limit flag (1),
/// Segment close receive channel flag (1),?
/// Segment close send channel flag (1),?
/// Document number (i),
/// [Segment offset (i)], all but first
/// [Document length (i)], until sender gets first ack
/// [Document parent (i)], first/once
/// [Document child memory limit (i)], first/once or not at all
/// [Document memory parent (i)], until sender gets first ack or not at all
/// [Segment length (i)],
/// }
///
/// Segment Frame {
/// Segment length type (2),
/// Segment has offset flag (1),
/// Segment has metadata flag (1),
/// Segment has custom memory limit flag (1),
/// Segment close receive channel flag (1),?
/// Segment close send channel flag (1),?
/// Document number (i),
/// [Document length (i)],
/// [Document allocation data (i)],
/// [Segment offset (i)],
/// [Segment length (i)],
/// }
///
/// Ack eliciting.
pub const VARIANT_SEGMENT: u8 = 0x01;
pub const VARIANT_SEGMENT_IS_TERMINATOR: u8 = 0x02;
pub const VARIANT_SEGMENT_HAS_TERMINATOR: u8 = 0x03;
pub const VARIANT_SEGMENT_FLAG_HAS_OFFSET: u8 = 0x04;
/// Closing is immediate, all sending and receiving child documents are dropped immediately. Child
/// documents have no in-order delivery guarantees beyond that they arrive after their parents.
/// We may need a soft close or more explicitly emphasized flushing within the implementation to
/// make the API for this more intuitive.
/// Document metadata includes a parent number and a document length.
///
/// A document may not start to be received unless a segment has this flag set and contains the
/// document's full length. Segments without a document length may have to be dropped due to a
/// document reset. Packets containing these segments must still be acked.
pub const VARIANT_SEGMENT_FLAG_HAS_METADATA: u8 = 0x08;
/// Types of memory limit changes: one-off change for application buffered recv, change only for
/// direct children. Other types cannot work since reordering prevents the receiver from always
/// having a child document's parent.
pub const VARIANT_SEGMENT_FLAG_HAS_LIMIT: u8 = 0x10;
pub const VARIANT_SEGMENT_FLAG_CLOSE_SEND: u8 = 0x20;
pub const VARIANT_SEGMENT_FLAG_CLOSE_RECV: u8 = 0x40;

pub const VARIANT_SEGMENT_BASE_MASK: u8 = 0x03;
pub const VARIANT_SEGMENT_MAX: u8 = 0x7F;
/// The sender will always be made aware of the receiver's current memory limits on all documents.
/// The sender must never allow more data to be in flight than the currently known receiver memory
/// limit.
///
/// This frame includes the minimum unseen recv doc no, all documents with a lower document number
/// are recieved using the previous memory limit, while all above will use the new memory limit.
/// This is to prevent deadlock caused by parent documents being rejected or reset
/// after a memory limit decrease, causing the child documents to be orphaned.
///
/// Ack eliciting.
pub const VARIANT_LIMIT_UPDATE_GENERAL: u8 = 0x80;
/// Ack eliciting.
pub const VARIANT_LIMIT_UPDATE_DOC: u8 = 0x81;

pub const VARIANT_ACK_SINGLE: u8 = 0x82;
pub const VARIANT_ACK_RUN: u8 = 0x83;

/// If an incoming document is smaller than our current memory limit, but would exceed the memory
/// limit when combined with all other recv docs, it is reset. Reset documents are sent again from
/// the start, while the receiver acts as though they were never received in the first place. The
/// sender may need to stall sending the reset document until it detects the sender
/// has sufficient memory to receive it. Under standard conditions this only happens if the local
/// memory limit has been reduced but the remote peer is not yet aware of this. We also reset
/// documents which specify parent numbers for documents that have been reset. The receiver may
/// choose to only reset the child documents of the newly received document if this would conserve
/// the memory limit.
///
/// The length and contents of a document must not change after a reset. If sending or receiving
/// were closed they must stay closed. Sending or receiving may be closed after a reset.
///
/// Ack eliciting.
pub const VARIANT_RESET_DOC: u8 = 0x85;

/// ?Ack eliciting.?
pub const VARIANT_FIN_DOC: u8 = 0x85;

/* MISC */

// TODO: Keep alive, explicit congestion, data blocked, connection close.

pub const MIN_FRAME_APPEND_LEN: usize = 20;
pub const MIN_MTU: usize = 128;
