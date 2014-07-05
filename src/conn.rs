use secretbox::SecretBox;
use crypto::salsa20::Salsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use handshake::{generate_public_key, generate_private_key, combine_keys, PUBLIC_KEY_SIZE};
use server::Server;
use std::slice;
use std::cmp::min;

pub struct Conn {
    state: ConnState,
    encryptor: SecretBox,
    decryptor: SecretBox,
    buffer: [u8, ..1024],
    buffered_count: uint,
}

pub enum ConnState {
    SendingClientHandshake,
    AwaitingClientHandshake,
    AwaitingServerHandshake,
    ReadingLength,
    ReadingData,
}

pub struct ActResult {
    plaintext_read: uint,
    ciphertext_read: uint,
    plaintext_written: uint,
    ciphertext_written: uint,
    identity_available: bool,
}

impl Conn {
    // Having the Conn start out with a key is temporary... we will need to key-exchange it
    fn new() -> Conn {
        let mut c = Conn{
            state: SendingClientHandshake,
            encryptor: SecretBox::new([0, ..32], [0, ..24]),
            decryptor: SecretBox::new([0, ..32], [0, ..24]),
            buffer: [0, ..1024],
            buffered_count: 0u,
        };

        // The public/private keys are stored at the end of the read buffer
        // before we've set up the encryptor and decryptor. I can't deal with
        // both slices at the same time because that looks like a data race,
        // so we store the public key in a temporary buffer. The public key
        // is stored here instead of the private key so that we don't have 
        // to worry about zeroing it out -- there does not seem to be a zeroing
        // function in rust-crypto yet. I assume zeroing out parts of the 
        // read buffer is not something the compiler can optimize out, so
        // erasing the private key from there should be OK.
        generate_private_key( c.mut_private_handshake_material() );
        let mut public_key : [u8, ..32] = [0, ..32];
        generate_public_key( public_key, c.private_handshake_material() );
        slice::bytes::copy_memory(c.mut_public_handshake_material(), public_key);
        c
    }

    fn new_on_server(server: &Server) {
        let mut c = Conn{
            state: AwaitingClientHandshake,
            encryptor: SecretBox::new([0, ..32], [0, ..24]),
            decryptor: SecretBox::new([0, ..32], [0, ..24]),
            buffer: [0, ..1024],
            buffered_count: 0u,
        };
        slice::bytes::copy_memory(c.mut_private_handshake_material(), server.private_key);
        slice::bytes::copy_memory(c.mut_public_handshake_material(), server.public_key);
    }

    fn mut_private_handshake_material<'a>(&'a mut self) -> &'a mut [u8] {
        self.buffer.mut_slice(1024-64, 1024-32)
    }
    fn private_handshake_material<'a>(&'a self) -> &'a [u8] {
        self.buffer.slice(1024-64, 1024-32)
    }
    fn mut_public_handshake_material<'a>(&'a mut self) -> &'a mut [u8] {
        self.buffer.mut_slice(1024-32, 1024)
    }
    fn public_handshake_material<'a>(&'a self) -> &'a [u8] {
        self.buffer.slice(1024-32, 1024)
    }



    fn initialize_crypters(&mut self, key: &[u8]) {
        let mut stream = Salsa20::new(key, [0, ..8]);
        let mut enc_key= [0, ..32];
        let mut dec_key= [0, ..32];
        stream.process([0, ..32], enc_key);
        stream.process([0, ..32], dec_key);
        self.encryptor = SecretBox::new(enc_key, [0, ..24]);
    }

    fn act(&mut self,
           plaintext_in: &[u8],
           ciphertext_in: &[u8],
           plaintext_out: &mut [u8],
           ciphertext_out: &mut [u8]) -> Option<ActResult> {
        let mut res = ActResult {
            plaintext_read: 0,
            ciphertext_read: 0,
            plaintext_written: 0,
            ciphertext_written: 0,
            identity_available: false,
        }; 
        match self.state {
            SendingClientHandshake => {
                // buffered_count is (ab)used to keep track of how much of the handshake we have sent.
                let want_to_send = PUBLIC_KEY_SIZE - self.buffered_count;
                let will_send = min(want_to_send, ciphertext_out.len());
                slice::bytes::copy_memory(
                    ciphertext_out.mut_slice(0, will_send), 
                    self.public_handshake_material().slice(
                        self.buffered_count, 
                        self.buffered_count + will_send));
                self.buffered_count += will_send;
                res.ciphertext_written += will_send;
                if self.buffered_count == PUBLIC_KEY_SIZE {
                    self.state = AwaitingServerHandshake;
                }
            }
            _ => {}
        }
        Some(res)
    }
}

#[cfg(test)]
mod test {
    use conn::{Conn};

    #[test]
    fn sends_public_key() {
        let mut c = Conn::new();
        let mut ciphertext : [u8, ..400] = [0, ..400];
        let res = c.act(vec!().as_slice(), vec!().as_slice(), vec!().as_mut_slice(), ciphertext).unwrap();
        
        assert_eq!(res.ciphertext_written, 32);
        assert_eq!(Vec::from_slice(ciphertext.slice(0, 32)), Vec::from_slice(c.public_handshake_material()));
    }

    #[test]
    fn sends_public_key_in_chunks() {
        let mut c = Conn::new();
        let mut ciphertext : [u8, ..400] = [0, ..400];
        let res1 = c.act(vec!().as_slice(), vec!().as_slice(), vec!().as_mut_slice(), ciphertext.mut_slice(0, 5)).unwrap();
        assert_eq!(res1.ciphertext_written, 5);
        let res2 = c.act(vec!().as_slice(), vec!().as_slice(), vec!().as_mut_slice(), ciphertext.mut_slice(5, 50)).unwrap();
        assert_eq!(res2.ciphertext_written, 27);
        
        assert_eq!(Vec::from_slice(ciphertext.slice(0, 32)), Vec::from_slice(c.public_handshake_material()));
    }
}

