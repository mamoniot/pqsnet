use dashmap::{DashMap, Entry};
use zeroize::Zeroizing;

use crate::{
    desegmentation::{self, Desegmentation},
    messages::*,
    session_layer::SessionLayer,
};

pub struct Context<S: SessionLayer> {
    init_table: DashMap<[u8; initialize::RESUMPTION_TOKEN_LEN], InitOptions>,
    socket_table: DashMap<u32, Socket<S>>,
}

struct InitOptions {
    resumption_key: Zeroizing<[u8; initialize::RESUMPTION_KEY_LEN]>,
    desegmentation: Option<Desegmentation>,
}

pub struct Socket<S: SessionLayer> {
    todo: S,
}

pub enum RecvResult<S: SessionLayer> {
    NewSocket(Socket<S>),
}

impl<S: SessionLayer> Context<S> {
    pub fn recv(&self, packet: &mut [u8]) -> RecvResult<S> {
        let key_id = u32::from_be_bytes(packet[KEY_ID_START..KEY_ID_END].try_into().unwrap());

        if key_id == initialize::NULL_KEY_ID {
            let resumption_token = packet[initialize::RESUMPTION_TOKEN_START..initialize::RESUMPTION_TOKEN_END]
                .try_into()
                .unwrap();

            // The following line locks init_table.
            // That lock is dropped before `process_initialize` is called.
            match self.init_table.entry(resumption_token) {
                Entry::Vacant(entry) => match Desegmentation::first_recv(packet) {
                    desegmentation::FirstRecvResult::Segmented(desegmentation) => {
                        entry.insert(InitOptions {
                            resumption_key: Default::default(),
                            desegmentation: Some(desegmentation),
                        });
                    }
                    desegmentation::FirstRecvResult::NotSegmented => {
                        drop(entry);

                        self.process_initialize(packet, &[0; initialize::RESUMPTION_KEY_LEN]);
                    }
                    desegmentation::FirstRecvResult::Invalid => todo!(),
                },
                Entry::Occupied(mut entry) => {
                    let init_options = entry.get_mut();
                    if let Some(desegmentation) = &mut init_options.desegmentation {
                        match desegmentation.recv(packet) {
                            desegmentation::RecvResult::Complete => {
                                let InitOptions { desegmentation, resumption_key } = entry.remove();
                                let message = desegmentation.expect("option occupancy confirmed above").complete();

                                self.process_initialize(message.as_ref(), resumption_key.as_slice());
                            }
                            desegmentation::RecvResult::Invalid => todo!(),
                            desegmentation::RecvResult::Duplicate => todo!(),
                            desegmentation::RecvResult::Incomplete => todo!(),
                        }
                    } else {
                        match Desegmentation::first_recv(packet) {
                            desegmentation::FirstRecvResult::Segmented(desegmentation) => {
                                init_options.desegmentation = Some(desegmentation);
                            }
                            desegmentation::FirstRecvResult::NotSegmented => {
                                let InitOptions { desegmentation: _, resumption_key } = entry.remove();

                                self.process_initialize(packet, resumption_key.as_slice());
                            }
                            desegmentation::FirstRecvResult::Invalid => todo!(),
                        }
                    }
                }
            }
        }

        todo!()
    }

    fn process_initialize(&self, _message: &[u8], _resumption_key: &[u8]) {

    }

    pub fn send() {}
}
