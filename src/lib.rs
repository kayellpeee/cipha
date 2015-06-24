#![feature(split_off)]
#![feature(append)]
mod cipher;

pub use cipher::feistel_encrypt;
pub use cipher::feistel_decrypt;

