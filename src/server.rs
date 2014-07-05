use handshake::{generate_public_key};

pub struct Server {
    pub private_key: [u8, ..32],
    pub public_key: [u8, ..32],
}

impl Server {
    fn new(private_key: [u8, ..32]) -> Server {
        let mut s = Server{
            private_key: private_key,
            public_key: [0, ..32],
        };
        generate_public_key(s.public_key, s.private_key);
        s
    }

}

