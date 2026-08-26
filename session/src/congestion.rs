pub struct CongestionControl {}

impl CongestionControl {
    pub fn current_available_plpmtus(&self, plpmtu: u32, now: f64) -> u32 {
        todo!()
    }

    pub fn congestion_detected(&self, now: f64) {
        todo!()
    }

    pub fn recover(&self, now: f64) {
        todo!()
    }

    pub fn sending(&self, packet_len: u32, now: f64) {
        todo!()
    }
}
