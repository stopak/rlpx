use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use primitive_types::{H128, H256};
use sha3::{Digest, Keccak256};

pub fn aes256_encrypt(key: H256, m: &mut [u8]) {
    let cipher = aes::Aes256::new(key.as_ref().into());
    let block = GenericArray::from_mut_slice(m);
    cipher.encrypt_block(block);
}

#[derive(Debug)]
pub struct Mac {
    secret: H256,
    hasher: Keccak256,
}

impl Mac {
    pub fn new(secret: H256) -> Self {
        Self {
            secret,
            hasher: Keccak256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn update_header(&mut self, header_ciphertext: &[u8]) {
        let mut header_mac_seed = self.digest().to_fixed_bytes();
        //header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16])
        aes256_encrypt(self.secret, &mut header_mac_seed);

        //^ header-ciphertext
        for i in ..header_ciphertext.len() {
            header_mac_seed[i] ^= header_ciphertext[i];
        }

        //egress-mac = keccak256.update(egress-mac, header-mac-seed)
        self.hasher.update(header_mac_seed);
    }

    pub fn update_body(&mut self, body_ciphertext: &[u8]) {
        self.hasher.update(body_ciphertext);

        let prev = self.digest();

        let mut encrypted = self.digest().to_fixed_bytes();
        aes256_encrypt(self.secret, &mut encrypted);

        for i in ..16 {
            encrypted[i] ^= prev[i];
        }
        self.hasher.update(encrypted);
    }

    /// keccak256.digest(egress-mac)[:16]
    pub fn digest(&self) -> H128 {
        H128::from_slice(&self.hasher.clone().finalize()[..16])
    }
}
