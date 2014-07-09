use handshake::{generate_public_key};
use std::slice;

pub struct Server {
    pub private_key: [u8, ..32],
    pub public_key: [u8, ..32],
}

impl Server {
    pub fn new(private_key: &[u8]) -> Server {
        assert!(private_key.len() == 32);
        let mut s = Server{
            private_key: [0, ..32],
            public_key: [0, ..32],
        };
        slice::bytes::copy_memory(s.private_key, private_key);
        generate_public_key(s.public_key, s.private_key);
        s
    }
}

