use crate::varint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelVariants {
    None = 0b00,
    Forward = 0b01,
    Backward = 0b10,
    Unbound = 0b11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DocNo(pub u64);

impl ChannelVariants {
    pub const NONE: u8 = 0b00;
    pub const FORWARD: u8 = 0b01;
    pub const BACKWARD: u8 = 0b10;
    pub const UNBOUND: u8 = 0b11;

    pub fn is_none(&self) -> bool {
        *self == ChannelVariants::None
    }

    pub fn is_some(&self) -> bool {
        *self != ChannelVariants::None
    }

    pub fn is_forward(&self) -> bool {
        *self == ChannelVariants::Forward
    }

    pub fn is_backward(&self) -> bool {
        *self == ChannelVariants::Backward
    }

    pub fn is_unbound(&self) -> bool {
        *self == ChannelVariants::Unbound
    }

    pub fn is_reply(&self) -> bool {
        *self as u8 >= ChannelVariants::Backward as u8
    }
}

impl DocNo {
    pub const MAX: u64 = varint::VARINT_MAX;

    pub fn try_new(no: u64) -> Option<DocNo> {
        (no <= Self::MAX).then_some(DocNo(no))
    }

    pub fn new(counter: u64, index: usize, variant: ChannelVariants, max_docs: usize) -> DocNo {
        debug_assert!(index < max_docs, "index must not be greater than max_docs");
        DocNo((counter * max_docs as u64 + index as u64) << 2 | variant as u64)
    }

    pub fn counter(&self, max_docs: usize) -> u64 {
        (self.0 >> 2) % max_docs as u64
    }

    pub fn index(&self, max_docs: usize) -> usize {
        ((self.0 >> 2) / max_docs as u64) as usize
    }

    pub fn variant_no(&self) -> u8 {
        (self.0 & 0b11) as u8
    }

    pub fn variant(&self) -> ChannelVariants {
        match self.variant_no() {
            ChannelVariants::NONE => ChannelVariants::None,
            ChannelVariants::FORWARD => ChannelVariants::Forward,
            ChannelVariants::BACKWARD => ChannelVariants::Backward,
            ChannelVariants::UNBOUND => ChannelVariants::Unbound,
            _ => unreachable!()
        }
    }
}
