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
    expected_count: uint, // bytes in the current segment being decoded, if state is ReadingData
}

pub enum ConnState {
    SendingClientHandshake,
    AwaitingClientHandshake,
    SendingServerHandshake,
    AwaitingServerHandshake,
    ReadingLength,
    ReadingData,
    CopyingPlaintext,
    Corrupt,
}

pub struct ActResult {
    pub plaintext_read: uint,
    pub ciphertext_read: uint,
    pub plaintext_written: uint,
    pub ciphertext_written: uint,
    pub identity_available: bool,
}

static BUFFER_CAPACITY: uint = 1024;
static MAC_LENGTH: uint = 16;
impl Conn {
    // Having the Conn start out with a key is temporary... we will need to key-exchange it
    pub fn new() -> Conn {
        let mut c = Conn{
            state: SendingClientHandshake,
            encryptor: SecretBox::new([0, ..32], [0, ..24]),
            decryptor: SecretBox::new([0, ..32], [0, ..24]),
            buffer: [0, ..BUFFER_CAPACITY],
            buffered_count: 0u,
            expected_count: 0u,
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
        println!("client public key: {}", Vec::from_slice(c.public_handshake_material()));
        println!("client private key: {}", Vec::from_slice(c.private_handshake_material()));
        c
    }

    pub fn new_on_server(server: &Server) -> Conn {
        let mut c = Conn{
            state: AwaitingClientHandshake,
            encryptor: SecretBox::new([0, ..32], [0, ..24]),
            decryptor: SecretBox::new([0, ..32], [0, ..24]),
            buffer: [0, ..1024],
            buffered_count: 0u,
            expected_count: 0u,
        };
        slice::bytes::copy_memory(c.mut_private_handshake_material(), server.private_key);
        slice::bytes::copy_memory(c.mut_public_handshake_material(), server.public_key);
        println!("server public key: {}", Vec::from_slice(c.public_handshake_material()));
        println!("server private key: {}", Vec::from_slice(c.private_handshake_material()));
        c
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

    fn erase_private_handshake_material(&mut self) {
        for b in self.mut_private_handshake_material().mut_iter() {
            *b = 0;
        }
    }


    fn initialize_crypters(&mut self, enc_first: bool) {
        println!("Initialze crypters!");
        let mut key : [u8, ..32] = [0, ..32];
        {
            let public_key = self.buffer.slice(0, 32);
            let private_key = self.private_handshake_material();
            println!("Combining {} and {}", Vec::from_slice(public_key), Vec::from_slice(private_key));
            combine_keys(key, public_key, private_key);
        }
        let mut stream = Salsa20::new(key, [0, ..8]);
        let mut enc_key = [0, ..32];
        let mut dec_key = [0, ..32];
        if enc_first {
            stream.process([0, ..32], enc_key);
            stream.process([0, ..32], dec_key);
        } else {
            stream.process([0, ..32], dec_key);
            stream.process([0, ..32], enc_key);
        }
        println!("Encrypt/decrypt keys: {} {}", Vec::from_slice(enc_key), Vec::from_slice(dec_key));
        self.encryptor = SecretBox::new(enc_key, [0, ..24]);
        self.decryptor = SecretBox::new(dec_key, [0, ..24]);
        self.erase_private_handshake_material();
    }

    fn accept_ciphertext(&mut self, count: uint, ciphertext_in: &[u8], res: &mut ActResult) -> bool {
        let available = ciphertext_in.len() - res.ciphertext_read;
        let more_wanted = min(BUFFER_CAPACITY, count) - self.buffered_count;
        let will_accept = min(available, more_wanted);
        slice::bytes::copy_memory(
            self.buffer.mut_slice(self.buffered_count, self.buffered_count + will_accept),
            ciphertext_in.slice(res.ciphertext_read, res.ciphertext_read + will_accept));
        res.ciphertext_read += will_accept;
        self.buffered_count += will_accept;
        return self.buffered_count == count;
    }

    fn send_public_key(&mut self, ciphertext_out: &mut [u8], res: &mut ActResult) -> bool {
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
        return self.buffered_count == PUBLIC_KEY_SIZE;
    }

    fn copy_plaintext_out(&mut self, plaintext_out: &mut [u8], res: &mut ActResult) -> bool {
        let want_to_send = self.buffered_count - self.expected_count;
        let will_send = min(want_to_send, plaintext_out.len() - res.plaintext_written);
        slice::bytes::copy_memory(
            plaintext_out.mut_slice(res.plaintext_written, res.plaintext_written + will_send),
            self.buffer.slice(self.expected_count, self.expected_count + will_send));
        self.expected_count += will_send;
        res.plaintext_written += will_send;
        return self.buffered_count == self.expected_count;
    }

    fn read_length(buf: &[u8]) -> uint {
        (buf[0] as uint) | ((buf[1] as uint) << 8)
    }

    fn to_length_buffer(len: uint) -> [u8, ..2] {
        [(len & 0xff) as u8, ((len >> 8) & 0xff) as u8]
    }

    fn detect_forgery(&mut self) -> bool {
        let mut plaintext : [u8, ..1024] = [0, ..1024];
        let decryption_result = {
            let ciphertext = self.buffer.slice(MAC_LENGTH, self.buffered_count);
            let mac = self.buffer.slice(0, MAC_LENGTH);
            println!("MAC={}, ciphertext={}", Vec::from_slice(mac), Vec::from_slice(ciphertext));
            // TODO: It would be nice to be able to decrypt in-place.
            self.decryptor.decrypt(plaintext.mut_slice(0, self.buffered_count - MAC_LENGTH), ciphertext, mac)
        };
        match decryption_result {
            None => {
                println!("De-authenced a chunk");
                slice::bytes::copy_memory(
                    self.buffer.mut_slice(MAC_LENGTH, self.buffered_count),
                    plaintext.slice(0, self.buffered_count - MAC_LENGTH));
                self.state = Corrupt;
                return false;
            }
            Some(_) => {
                println!("De-authenc failed");
                return true;
            }
        }
    }

    fn pipe_ready(&self) -> bool {
        match self.state {
            SendingClientHandshake => false,
            AwaitingClientHandshake => false,
            SendingServerHandshake => true,
            AwaitingServerHandshake => false,
            ReadingLength => true,
            ReadingData => true,
            CopyingPlaintext => true,
            Corrupt => false,
        }
    }

    fn authencrypted_write(&mut self, ciphertext: &mut [u8], plaintext: &[u8], res: &mut ActResult) {
        let mut mac : [u8, ..MAC_LENGTH] = [0, ..MAC_LENGTH];
        let mac_begin = res.ciphertext_written;
        let encrypted_begin = mac_begin + MAC_LENGTH;
        self.encryptor.encrypt(
            plaintext, //plaintext_in.slice(0, will_send),
            ciphertext.mut_slice(encrypted_begin, encrypted_begin + plaintext.len()),
            mac);

        println!("Will send {} bytes of ciphertext. Also, the MAC is {}", plaintext.len(), Vec::from_slice(mac));
        slice::bytes::copy_memory(ciphertext.mut_slice(mac_begin, mac_begin + MAC_LENGTH), mac);
        res.ciphertext_written += MAC_LENGTH + plaintext.len();
    }

    pub fn act(&mut self,
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
        loop {
            match self.state {
                SendingClientHandshake => {
                    if self.send_public_key(ciphertext_out, &mut res) {
                        self.state = AwaitingServerHandshake;
                        self.buffered_count = 0;
                    } else {
                        break;
                    }
                }
                AwaitingClientHandshake => {
                    if self.accept_ciphertext(32, ciphertext_in, &mut res) {
                        self.initialize_crypters(false);
                        self.state = SendingServerHandshake;
                        self.buffered_count = 0;
                    } else {
                        break;
                    }
                }
                SendingServerHandshake => {
                    if self.send_public_key(ciphertext_out, &mut res) {
                        self.state = ReadingLength;
                        self.buffered_count = 0;
                    } else {
                        break;
                    }
                }
                AwaitingServerHandshake => {
                    if self.accept_ciphertext(32, ciphertext_in, &mut res) {
                        self.initialize_crypters(true);
                        self.state = ReadingLength;
                        self.buffered_count = 0;
                    } else {
                        break;
                    }
                }
                ReadingLength => {
                    println!("ReadingLength");
                    if self.accept_ciphertext(2 + MAC_LENGTH, ciphertext_in, &mut res) {
                        if self.detect_forgery() {
                            println!("Forgery detected");
                            return None;
                        }
                        self.expected_count = Conn::read_length(self.buffer.slice(MAC_LENGTH,MAC_LENGTH+2));
                        self.state = ReadingData;
                        self.buffered_count = 0;
                    } else {
                        break;
                    }
                }
                ReadingData => {
                    let c = self.expected_count + MAC_LENGTH;
                    if self.accept_ciphertext(c, ciphertext_in, &mut res) {
                        if self.detect_forgery() {
                            return None;
                        }
                        self.state = CopyingPlaintext;
                        self.expected_count = MAC_LENGTH;
                    } else {
                        break;
                    }
                }
                CopyingPlaintext => {
                    if self.copy_plaintext_out(plaintext_out, &mut res) {
                        self.buffered_count = 0;
                        self.state = ReadingLength;
                    } else {
                        break;
                    }
                }
                Corrupt => {
                    return None;
                }
            }
        }

        if self.pipe_ready() {
            // Per-packet overhead is: mac(length), length, mac(data)
            let packet_overhead = MAC_LENGTH + MAC_LENGTH + 2;
            if ciphertext_out.len() > packet_overhead + res.ciphertext_written && plaintext_in.len() > 0 {
                let will_send = min(plaintext_in.len(), ciphertext_out.len() - packet_overhead);

                self.authencrypted_write(ciphertext_out, Conn::to_length_buffer(will_send), &mut res);
                self.authencrypted_write(ciphertext_out, plaintext_in.slice(0, will_send), &mut res);
                res.plaintext_read += will_send;
            }
        }

        Some(res)
    }
}

#[cfg(test)]
mod test {
    use conn::{Conn};
    use server::{Server};

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

    #[test]
    fn simple_exchange() {
        let server = Server::new("123456789 123456789 123456789 12".as_bytes());
        let mut sconn = Conn::new_on_server(&server);
        let mut cconn = Conn::new();
        let mut ciphertext_s_to_c : [u8, ..500] = [0, ..500];
        let mut ciphertext_c_to_s : [u8, ..500] = [0, ..500];
        let plaintext_for_server : [u8, ..400] = [8, ..400];
        let plaintext_for_client : [u8, ..300] = [3, ..300];
        let mut plaintext_from_server : [u8, ..800] = [0, ..800];
        let mut plaintext_from_client : [u8, ..800] = [0, ..800];

        let mut cres;
        let mut sres;
        cres = cconn.act(
            plaintext_for_server,
            ciphertext_s_to_c.slice(0,0),
            plaintext_from_server,
            ciphertext_c_to_s).unwrap();
        assert_eq!(cres.ciphertext_read, 0);
        assert_eq!(cres.ciphertext_written, 32); // should have sent the handshake
        assert_eq!(cres.plaintext_written, 0);
        assert_eq!(cres.plaintext_read, 0);

        sres = sconn.act(
            plaintext_for_client.slice(0, 300),
            ciphertext_c_to_s.slice(0, cres.ciphertext_written),
            plaintext_from_client,
            ciphertext_s_to_c).unwrap();
        assert_eq!(sres.ciphertext_read, 32);
        assert_eq!(sres.plaintext_read, 300);
        assert_eq!(sres.plaintext_written, 0);
        assert_eq!(sres.ciphertext_written, 300 + 32 + 16 + 16 + 2);

        // Receive everything they sent, and sent with just a small buffer
        cres = cconn.act(
            plaintext_for_server,
            ciphertext_s_to_c.slice(0, sres.ciphertext_written),
            plaintext_from_server,
            ciphertext_c_to_s.mut_slice(0, 134)).unwrap();
        assert_eq!(cres.ciphertext_read, sres.ciphertext_written);
        assert_eq!(cres.plaintext_written, 300);
        assert_eq!(cres.plaintext_read, 100);
        assert_eq!(cres.ciphertext_written, 134);

        // Send some more.
        cres = cconn.act(
            plaintext_for_server.slice(100, plaintext_for_server.len()),
            vec!().as_slice(),
            plaintext_from_server.mut_slice(300, 800),
            ciphertext_c_to_s.mut_slice(134, 500)).unwrap();
        assert_eq!(cres.ciphertext_read, 0); // we didn't give it any new ciphertext
        assert_eq!(cres.ciphertext_written, 334);
        assert_eq!(cres.plaintext_read, 300);
        assert_eq!(cres.plaintext_written, 0);

        // Receive everything on the server
        sres = sconn.act(
            plaintext_for_client.slice(300, 300),
            ciphertext_c_to_s.slice(0, 134 + 334),
            plaintext_from_client,
            ciphertext_s_to_c).unwrap();
        assert_eq!(sres.ciphertext_read, 134 + 334);
        assert_eq!(sres.plaintext_written, 400);
        assert_eq!(sres.ciphertext_written, 0);
        assert_eq!(sres.plaintext_read, 0);

        assert_eq!(Vec::from_slice(plaintext_from_client.slice(0, plaintext_for_server.len())), Vec::from_slice(plaintext_for_server));
        assert_eq!(Vec::from_slice(plaintext_from_server.slice(0, plaintext_for_client.len())), Vec::from_slice(plaintext_for_client));
    }
}

