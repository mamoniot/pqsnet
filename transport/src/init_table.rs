use std::sync::{Mutex, MutexGuard};

const BUCKET_SIZE: usize = 8;

pub struct InitTable<T> {
    table: Vec<Mutex<Bucket<T>>>,
    mask: u32,
}

struct Bucket<T> {
    ids: [u64; BUCKET_SIZE],
    last_use: [i32; BUCKET_SIZE],
    table: [Option<T>; BUCKET_SIZE],
    counter: i32,
}

impl<T> Default for Bucket<T> {
    fn default() -> Self {
        Self {
            ids: Default::default(),
            table: Default::default(),
            last_use: Default::default(),
            counter: 0,
        }
    }
}

pub enum Entry<'a, T> {
    Occupied(OccupiedEntry<'a, T>),
    Vacant(VacantEntry<'a, T>),
}

pub struct VacantEntry<'a, T> {
    bucket: MutexGuard<'a, Bucket<T>>,
    i: usize,
    id: u64,
}

pub struct OccupiedEntry<'a, T> {
    bucket: MutexGuard<'a, Bucket<T>>,
    i: usize,
}

impl<'a, T> VacantEntry<'a, T> {
    pub fn insert(mut self, v: T) {
        self.bucket.ids[self.i] = self.id;
        self.bucket.last_use[self.i] = self.bucket.counter;
        self.bucket.table[self.i] = Some(v);
    }
}

impl<'a, T> OccupiedEntry<'a, T> {
    pub fn get_mut(&mut self) -> &mut T {
        self.bucket.table[self.i].as_mut().unwrap()
    }

    pub fn remove(&mut self) -> T {
        // "last_use" is the last use of the table index, not the entry.
        self.bucket.table[self.i].take().unwrap()
    }
}

impl<T> InitTable<T> {
    pub fn new(&self, max_size: u32) -> Self {
        debug_assert!(max_size > 0);
        let lg_size = max_size.ilog2();
        let size = (1u32 << lg_size) / BUCKET_SIZE as u32;

        let mut table = Vec::new();
        table.resize_with(size as usize, Default::default);
        Self { table, mask: size - 1 }
    }

    pub fn entry(&self, id: u64) -> Entry<T> {
        let idx = (id as u32 & self.mask) as usize;
        let mut bucket = self.table[idx].lock().unwrap();

        let mut lru_age = bucket.last_use[0];
        let mut lru_idx = 0;
        bucket.counter = bucket.counter.wrapping_add(1);
        for i in 0..BUCKET_SIZE {
            if bucket.ids[i] == id && bucket.table[i].is_some() {
                bucket.last_use[i] = bucket.counter;
                return Entry::Occupied(OccupiedEntry { bucket, i });
            }
            if lru_age.wrapping_sub(bucket.last_use[i]) > 0 {
                lru_age = bucket.last_use[i];
                lru_idx = i;
            }
        }

        Entry::Vacant(VacantEntry { bucket, i: lru_idx, id })
    }
}
