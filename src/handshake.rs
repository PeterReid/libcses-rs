use std::rand;
use std::rand::Rng;

pub static PUBLIC_KEY_SIZE: uint = 32;

pub fn generate_private_key(buf: &mut [u8]) {
    let mut rng = rand::task_rng();
    rng.fill_bytes(buf);
}

pub fn generate_public_key(public_key: &mut[u8], private_key: &[u8]) {
    for (public_byte, private_byte) in public_key.mut_iter().zip(private_key.iter()) {
        *public_byte = 0xff ^ *private_byte;
    }
}

pub fn combine_keys(shared_secret: &mut[u8], public_key: &[u8], private_key: &[u8]) {
    for ((s, pu), pr) in shared_secret.mut_iter().zip(public_key.iter()).zip(private_key.iter()) {
        *s = *pu ^ *pr;
    }
}

