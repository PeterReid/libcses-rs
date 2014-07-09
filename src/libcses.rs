extern crate crypto = "rust-crypto";
extern crate rand;

//use secretbox::{SecretBox, EncryptError, DecryptError};
//use conn::{Conn};
//use secretbox::test::{ nacl_comparison};
use conn::Conn;
use server::Server;

pub mod secretbox;
pub mod conn;
pub mod handshake;
pub mod server;


fn main() {
    println!("hello world");
}
