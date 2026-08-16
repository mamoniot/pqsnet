/* START OF PAYLOAD FRAME VARIANTS */

pub const VARIANT_NULL_TERMINATOR: u8 = 0x0;
pub const VARIANT_PADDING: u8 = 0xFF;

pub const VARIANT_SEGMENT: u8 = 0x01;
pub const VARIANT_SEGMENT_IS_TERMINATOR: u8 = 0x02;
pub const VARIANT_SEGMENT_HAS_TERMINATOR: u8 = 0x03;
pub const VARIANT_SEGMENT_FLAG_CLOSE_SEND: u8 = 0x04;
pub const VARIANT_SEGMENT_FLAG_CLOSE_RECV: u8 = 0x08;
pub const VARIANT_SEGMENT_BASE_MASK: u8 = 0x03;
pub const VARIANT_SEGMENT_MAX: u8 = 0x10;

pub const VARIANT_ACK_SINGLE: u8 = 0x10;
pub const VARIANT_ACK_RUN: u8 = 0x11;
/// If the receiver's memory limit has decreased before the sender is aware or the receiver is out
/// of memory despite the memory limit, then these frame variants are sent instead of acks to inform
/// the sender that the packets were received but were not committed to memory.
/// TODO: This component of the protocol is necessary but insufficient for elegantly handling a
/// global out of memory event, we need just a bit more for handling this case.
pub const VARIANT_STALL_SINGLE: u8 = 0x12;
pub const VARIANT_STALL_RUN: u8 = 0x13;

// Types of memory limit changes: one-off change for application buffered recv, change only for direct children, change for all new descendants, retroactive change for all descendants, overriding change for all descendants.

/// If an incoming document is larger than our current memory limit, we reject it.
/// However, when sending a document, the sender may allow child documents sent back in reply to
/// occupy a separate memory limit, possibly even a separate memory space, than the global memory
/// limit. Sending a document and setting the distinct memory limit of its child reply documents
/// must be combinable as an atomic operation, otherwise the short delay between sending the document
/// and then modifying the memory limit of child documents would introduce a rare race condition
/// where a child document arrives before the application successfully raised the document memory
/// limit. Thus the child document would inherent the session level memory limit incorrectly an so
/// may be suriously rejected.
pub const VARIANT_REJECT: u8 = 0x13;

// TODO: Keep alive, explicit congestion, data blocked, connection close.

pub const MIN_FRAME_APPEND_LEN: usize = 20;
pub const MIN_MTU: usize = 128;

pub const MAX_DOC_HEADER_LEN: usize = 8 * 2;
