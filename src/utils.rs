pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;

use aes::cipher::{KeyIvInit, StreamCipher};
use secp256k1::{SecretKey, PublicKey, SECP256K1};
use primitive_types::{H256, H128};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use std::error::Error;

use crate::errors::Errors;

/// Converts public key of length 64 to 65 that can be used by PublicKey
pub fn get_public_key(data: &[u8]) -> Result<PublicKey, Box<dyn Error>> {
    if data.len() != 64 {
        return Err(Box::new(Errors::PublicKeyError));
    }

    let mut s = [0_u8; 65];
    s[0] = 4;
    s[1..].copy_from_slice(data);

    let pub_k = PublicKey::from_slice(&s)?;
    Ok(pub_k)
}

pub fn get_shared_key(private_key: &SecretKey, public_key: &PublicKey) -> H256 {
    H256::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, private_key)[..32])
}

/// Calculates signature using provided private key and SECP256K1
/// Secp256k1 lib returns two values, signature and recovery_id
/// this function concatenates those two values, recovery id is appended at the end of signature
pub fn get_recoverable_signature(msg: &[u8], private_key: &SecretKey) -> [u8; 65] {
    let (rec_id, sig) = SECP256K1
        .sign_ecdsa_recoverable(&secp256k1::Message::from_slice(msg).unwrap(), private_key)
        .serialize_compact();

    let mut sig_bytes = [0_u8; 65];
    sig_bytes[..64].copy_from_slice(&sig);
    sig_bytes[64] = rec_id.to_i32() as u8;

    sig_bytes
}

/// the NIST SP 800-56 Concatenation Key Derivation Function
/// NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
pub fn kdf(secret: H256, s1: &[u8], dest: &mut [u8]) {
    let mut digest = Sha256::default();
    let mut counter: u32 = 1;

    for chunk in dest.chunks_mut(sha2::Sha256::output_size()) {
        sha2::digest::Update::update(&mut digest, &counter.to_be_bytes());
        sha2::digest::Update::update(&mut digest, secret.as_bytes());
        sha2::digest::Update::update(&mut digest, s1);
        chunk.copy_from_slice(&digest.finalize_reset()[..chunk.len()]);
        counter += 1;
    }
}

pub fn sha256(data: &[u8]) -> H256 {
    H256::from(Sha256::digest(data).as_ref())
}

pub fn mac(key: &[u8], input: &[&[u8]], auth_data: &[u8]) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_data);
    H256::from_slice(&hmac.finalize().into_bytes())
}


pub fn aes_ctr(key: H128, iv: H128, m: &mut [u8]) {
    let mut cipher = Aes128Ctr64BE::new(key.as_ref().into(), iv.as_ref().into());
    cipher.apply_keystream(m);
}



/// Convenience function for calculation of keccak256 hash
pub fn keccak256(data: &[&[u8]]) -> H256 {
    let mut hasher = Keccak256::new();
    for i in data {
        hasher.update(i);
    }
    H256::from(hasher.finalize().as_ref())
}