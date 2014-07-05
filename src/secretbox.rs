// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crypto::poly1305::Poly1305;
use crypto::salsa20::Salsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::mac::{Mac, MacResult};
use std::slice;

pub struct SecretBox {
    key: [u8, ..32],
    nonce: [u8, ..24],
}

fn increment_nonce(nonce: &mut [u8]) {
    let mut increment: u8 = 1;

    for b in nonce.mut_iter() {
        *b += increment;
        increment = increment & (((256 - (*b as uint)) >> 8) as u8);
    }
}

#[deriving(PartialEq, Eq, Show)]
pub enum EncryptError {
    MisusedEncryption
}

#[deriving(PartialEq, Eq, Show)]
pub enum DecryptError {
    MisusedDecryption,
    Forged
}

impl SecretBox {
    pub fn new(key: &[u8], nonce: &[u8]) -> SecretBox {
        assert!(key.len() == 32);
        assert!(nonce.len() == 24);
        let mut b = SecretBox {
            key: [0, ..32],
            nonce: [0, ..24],
        };

        slice::bytes::copy_memory(b.key, key);
        slice::bytes::copy_memory(b.nonce, nonce);
        b
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8], mac: &mut[u8]) -> Option<EncryptError> {
        if mac.len() != 16 {
            return Some(MisusedEncryption);
        }
        if plaintext.len() != ciphertext.len() {
            return Some(MisusedEncryption);
        }
        let mut auth_key : [u8, ..32] = [0, ..32];

        let mut stream = Salsa20::new_xsalsa20(self.key, self.nonce);
        stream.process([0, ..32], auth_key);
        stream.process(plaintext, ciphertext);

        let mut authenticator = Poly1305::new(auth_key);
        authenticator.input(ciphertext);
        authenticator.raw_result(mac);

        increment_nonce(self.nonce);

        None
    }

    pub fn decrypt(&mut self, plaintext: &mut [u8], ciphertext: &[u8], mac: &[u8]) -> Option<DecryptError> {
        if mac.len() != 16 {
            return Some(MisusedDecryption);
        }
        if plaintext.len() != ciphertext.len() {
            return Some(MisusedDecryption);
        }

        let mut auth_key : [u8, ..32] = [0, ..32];

        let mut stream = Salsa20::new_xsalsa20(self.key, self.nonce);
        stream.process([0, ..32], auth_key);

        let mut authenticator = Poly1305::new(auth_key);
        authenticator.input(ciphertext);
        if MacResult::new(mac) != authenticator.result() {
            return Some(Forged);
        }
        
        stream.process(ciphertext, plaintext);

        increment_nonce(self.nonce);

        None
    }
}

#[cfg(test)]
mod test {
    use std::rand;
    use std::rand::Rng;
    use secretbox::{SecretBox, MisusedEncryption, MisusedDecryption, Forged};

    #[test]
    fn inverts() {
        let mut rng = rand::task_rng();
        for _ in range(0u, 50u) {
            let message_length: uint = rng.gen::<uint>() % 1000 + 50;
            let plaintext : Vec<u8> = Vec::from_fn(message_length, |_| rng.gen());
            let mut mac = [0, ..16];
            let mut ciphertext = Vec::from_fn(message_length, |_| 0);
            let key = Vec::from_fn(32, |_| rng.gen());
            let nonce = Vec::from_fn(24, |_| rng.gen());
            let mut encryptor = SecretBox::new(key.as_slice(), nonce.as_slice());
            let mut decryptor = SecretBox::new(key.as_slice(), nonce.as_slice());
            let mut decrypted = Vec::from_fn(message_length, |_| 0);

            encryptor.encrypt(plaintext.as_slice(), ciphertext.as_mut_slice(), mac.as_mut_slice());
            decryptor.decrypt(decrypted.as_mut_slice(), ciphertext.as_slice(), mac.as_slice());
            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn nacl_comparison() {
        // Compare with nacl's xsalsa20poly1305 implementation.

        let key : Vec<u8> = vec!(
             0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
            ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
            ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
            ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
        );
        let nonce : Vec<u8> = vec!(
             0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
            ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
            ,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
        );
        let plaintext : Vec<u8> = vec!(
             0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
            ,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
            ,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
            ,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
            ,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
            ,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
            ,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
            ,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
            ,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
            ,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
            ,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
            ,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
            ,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
            ,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
            ,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
            ,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
            ,0x5e,0x07,0x05
        );
        let expected_mac : Vec<u8> = vec!(
             0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
            ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
        );
        let expected_encryption : Vec<u8> = vec!(
             0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
            ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
            ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
            ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
            ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
            ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
            ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
            ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
            ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
            ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
            ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
            ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
            ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
            ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
            ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
            ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
            ,0xe3,0x55,0xa5
        );
        let mut encryptor = SecretBox::new(key.as_slice(), nonce.as_slice());
        let mut ciphertext = Vec::from_fn(plaintext.len(), |_| 0);
        let mut mac = Vec::from_fn(16, |_| 0);
        
        encryptor.encrypt(plaintext.as_slice(), ciphertext.as_mut_slice(), mac.as_mut_slice());
        assert_eq!(ciphertext, expected_encryption);
        assert_eq!(mac, expected_mac);
    }

    #[test]
    fn length_checks() {
        let mut b = SecretBox::new([0, ..32], [0, ..24]);

        // Encryption with different plaintext and ciphertext lengths
        assert_eq!(b.encrypt([0, ..120], [0, ..121], [0, ..16]), Some(MisusedEncryption));
        assert_eq!(b.encrypt([0, ..121], [0, ..120], [0, ..16]), Some(MisusedEncryption));
        // Encryption with wrong MAC length
        assert_eq!(b.encrypt([0, ..120], [0, ..120], [0, ..15]), Some(MisusedEncryption));
        assert_eq!(b.encrypt([0, ..120], [0, ..120], [0, ..17]), Some(MisusedEncryption));

        // Decryption with different plaintext and ciphertext lengths
        assert_eq!(b.decrypt([0, ..121], [0, ..120], [0, ..16]), Some(MisusedDecryption));
        assert_eq!(b.decrypt([0, ..120], [0, ..121], [0, ..16]), Some(MisusedDecryption));
        // Decryption with wrong MAC length
        assert_eq!(b.decrypt([0, ..120], [0, ..120], [0, ..15]), Some(MisusedDecryption));
        assert_eq!(b.decrypt([0, ..120], [0, ..120], [0, ..17]), Some(MisusedDecryption));
    }

    #[test]
    fn forgery_detection() {
        let mut mac : [u8, ..16] = [0, ..16];
        let plaintext : [u8, ..500] = [0x45, ..500];
        let mut ciphertext : [u8, ..500] = [0, ..500];

        let key = "a 32-byte key. a 32-byte key. a ".as_bytes();
        let nonce = "a 24-byte nonce. a 24-by".as_bytes();

        let mut encryptor = SecretBox::new(key, nonce);
        let mut decryptor = SecretBox::new(key, nonce);

        encryptor.encrypt(plaintext, ciphertext, mac);
        mac[7] += 1;
        assert_eq!(decryptor.decrypt([0, ..500], ciphertext, mac), Some(Forged));
    }

    #[test]
    fn nonce_autoincrements() {
        let plaintext : Vec<u8> = Vec::from_fn(20, |i| (i*7) as u8);
        let mut ciphertext1 : [u8, ..20] = [0, ..20];
        let mut mac1 : [u8, ..16] = [0, ..16];

        let key = "a 32-byte key. a 32-byte key. a ".as_bytes();
        let nonce = "a 24-byte nonce. a 24-by".as_bytes();

        let mut encryptor = SecretBox::new(key, nonce);
        let mut decryptor = SecretBox::new(key, nonce);

        assert_eq!(encryptor.encrypt(plaintext.as_slice(), ciphertext1, mac1), None);


        let mut decrypted : Vec<u8> = Vec::from_fn(20, |_| 0);
        assert_eq!(decryptor.decrypt(decrypted.as_mut_slice(), ciphertext1, mac1), None);
        assert_eq!(plaintext, decrypted);

        // Encrypt 300 times, making some the ciphertext doesn't repeat.
        // 300 is mildly interesting because it makes sure the nonce increment
        // at least involves multiple bytes.
        for _ in range(0, 300u) {
          let mut ciphertext2 : [u8, ..20] = [0, ..20];
          let mut mac2 : [u8, ..16] = [0, ..16];
          assert_eq!(encryptor.encrypt(plaintext.as_slice(), ciphertext2, mac2), None);

          assert!(ciphertext1 != ciphertext2);

          assert_eq!(decryptor.decrypt(decrypted.as_mut_slice(), ciphertext2, mac2), None);
          assert_eq!(plaintext, decrypted);
        }
    }
}

