use std::sync::atomic::{AtomicU32, Ordering::*};

use crate::protocol::flags::AES_GCM_INIT_COUNTER;

pub struct Antireplay<const L: usize>([AtomicU32; L]);

impl<const L: usize> Default for Antireplay<L> {
    fn default() -> Self {
        const { assert!(AES_GCM_INIT_COUNTER > 0 && L > 0 && L.next_power_of_two() == L) }
        Self(std::array::from_fn(|_| AtomicU32::new(0)))
    }
}

impl<const L: usize> Antireplay<L> {
    /// Deterministically map a counter to an antireplay slot.
    /// In order to avoid cache line invalidation contention, counters are mapped to slots in
    /// reverse bit order, so that adjacent counters are maximally non-adjacent in memory.
    ///
    /// For example, if `L == 8`, counter values 0..8 would be mapped to the following sequence of indices:
    /// 0, 4, 2, 6, 1, 5, 3, 7.
    ///
    /// TODO: Benchmark this strategy against no strategy.
    fn slot(&self, counter: u32) -> &AtomicU32 {
        let i = counter.reverse_bits() >> (32 - L.ilog2());
        &self.0[i as usize]
    }
    /// Check whether the given `counter` has been replayed without mutating state.
    /// If the value of `counter` has ever been passed to `update` before, this will return false.
    /// This may return false even if `counter` has not been passed to `update` before.
    pub fn check(&self, counter: u32) -> bool {
        let slot = self.slot(counter);
        let pre_counter = slot.load(Relaxed);
        pre_counter < counter
    }
    /// Check whether the given `counter` has been replayed,
    /// and update this antireplay with it if it has not been.
    /// If the value of `counter` has ever been passed to `update` before, this will return false.
    /// This may return false even if `counter` has not been passed to `update` before.
    ///
    /// This function should not be called until after `counter` is cryptographically authenticated.
    pub fn update(&self, counter: u32) -> bool {
        let slot = self.slot(counter);
        let pre_counter = slot.fetch_max(counter, Relaxed);
        pre_counter < counter
    }
}
