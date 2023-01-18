use std::error::Error;

use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use primitive_types::{H128, H256};
use rlp::{Rlp, RlpStream};
use secp256k1::{PublicKey, SecretKey, SECP256K1};

use crate::errors::ECIESError;
use crate::mac::Mac;
use crate::utils::*;

#[allow(dead_code)]
pub struct Secrets {
    aes: H256,
    mac: H256,

    ingress_mac: Mac,
    egress_mac: Mac,

    ingress_aes: Aes256Ctr64BE,
    egress_aes: Aes256Ctr64BE,
}

pub struct Ecies {
    /// Local private key
    private_key: SecretKey,
    /// Local public key, calculated based on privded private_key
    pub public_key: PublicKey,
    /// Random private key, calculated on auth message creation
    ephemeral_private_key: SecretKey,

    /// local nonce
    nonce: H256,

    /// Remote public key, provided by external means
    remote_public_key: PublicKey,
    /// Remote ephemeral public key
    remote_ephemeral_public_key: Option<PublicKey>,

    /// remote nonce, received by ACK
    remote_nonce: Option<H256>,

    /// elliptic curve Diffie-Hellman key agreement between PRIVKEY and PUBKEY. (only X on curve)
    static_shared_key: H256, //key agreement between local private key and remote public key
    /// ephemeral shared key
    ephemeral_shared_key: Option<H256>,

    secrets: Option<Secrets>,

    init_msg: Option<Bytes>,
    ack_msg: Option<Bytes>,
}

impl Ecies {
    pub fn new(
        private_key: SecretKey,
        remote_public_key: PublicKey,
    ) -> Result<Self, Box<dyn Error>> {
        let random_private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        Self::create(private_key, remote_public_key, random_private_key)
    }

    pub fn create(
        private_key: SecretKey,
        remote_public_key: PublicKey,
        random_private_key: SecretKey,
    ) -> Result<Self, Box<dyn Error>> {
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        let static_shared_key = get_shared_key(&private_key, &remote_public_key);

        Ok(Self {
            private_key,
            public_key,
            ephemeral_private_key: random_private_key,
            nonce: H256::random(),

            remote_public_key,
            remote_ephemeral_public_key: None,
            remote_nonce: None,

            static_shared_key,
            ephemeral_shared_key: None,

            secrets: None,

            init_msg: None,
            ack_msg: None,
        })
    }


    pub fn get_auth_body(&self) -> BytesMut {
        let msg = self.static_shared_key ^ self.nonce;

        //Signature recoverable (ETH style) for the provided message, use newly generated private_key
        let sig = get_recoverable_signature(msg.as_bytes(), &self.ephemeral_private_key);

        let full = self.public_key.serialize_uncompressed();

        let pubk = &full[1..];

        let mut stream = RlpStream::new_list(4);
        stream.append(&&sig[..]); //signature 65 bytes
        stream.append(&pubk); //publickey 64 bytes
        stream.append(&self.nonce.as_bytes()); //nonce
        stream.append(&4u8); //protocol version

        // auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
        let mut auth_body = stream.out();
        // add padding 0 bytes, 122 is a random value
        auth_body.resize(auth_body.len() + 122, 0);

        auth_body

        //Get RLP encoded auth body
    }

    pub fn get_auth_encrypted(&mut self) -> BytesMut {
        let auth = self.get_auth_body();
        let encrypted = self.encrypt(auth);

        self.init_msg = Some(Bytes::copy_from_slice(&encrypted[..]));

        encrypted
    }

    pub fn read_ack_encrypted(
        &mut self,
        buf: &mut [u8],
        read_bytes: &mut u16,
    ) -> Result<(), Box<dyn Error>> {
        let payload_size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        self.ack_msg = Some(Bytes::copy_from_slice(&buf[0..payload_size + 2]));

        let ack_msg = self.decrypt(buf, read_bytes)?;
        self.read_ack(ack_msg)?;

        Ok(())
    }

    /// Read ACK data, parse remote public_key, remote nonce and vsn
    /// calculate ephemeral shared key used for mac calculations
    pub fn read_ack(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let data_rlp = Rlp::new(data);

        if !data_rlp.is_list() {
            return Err(Box::new(ECIESError::InvalidAckRlpData));
        } else {
            let pub_key: Vec<u8> = data_rlp.val_at(0)?;
            let nonce: Vec<u8> = data_rlp.val_at(1)?;
            // let vsn: Vec<u8> = data.val_at(2)?;

            let mut s = [0_u8; 65];
            s[0] = 4;
            s[1..].copy_from_slice(&pub_key);
            let ephemeral_pub_key = PublicKey::from_slice(&s)?;

            self.remote_ephemeral_public_key = Some(ephemeral_pub_key);
            let remote_nonce = H256::from_slice(&nonce);
            self.remote_nonce = Some(remote_nonce); //save remote nonce for mac calculation

            // Generate secrets
            self.ephemeral_shared_key = Some(get_shared_key(
                &self.ephemeral_private_key,
                &ephemeral_pub_key,
            ));

            let shared_secret = keccak256(&[remote_nonce.as_bytes(), self.nonce.as_bytes()]);
            let shared_secret = keccak256(&[
                self.ephemeral_shared_key.unwrap().as_bytes(),
                shared_secret.as_bytes(),
            ]);

            let aes_secret = keccak256(&[
                self.ephemeral_shared_key.unwrap().as_bytes(),
                shared_secret.as_bytes(),
            ]);
            let mac_secret = keccak256(&[
                self.ephemeral_shared_key.unwrap().as_bytes(),
                aes_secret.as_bytes(),
            ]);

            let iv = H128::default();

            let mut s = Secrets {
                aes: aes_secret,
                mac: mac_secret,

                egress_mac: Mac::new(mac_secret),
                ingress_mac: Mac::new(mac_secret),

                // ingress_aes: aes::Aes256::new(GenericArray::from_slice(aes_secret.as_bytes())),
                // egress_aes: aes::Aes256::new(GenericArray::from_slice(aes_secret.as_bytes())),
                ingress_aes: Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into()),
                egress_aes: Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into()),
            };

            // s.egress_mac.update((mac_secret ^ self.nonce).as_bytes());
            s.egress_mac.update((mac_secret ^ remote_nonce).as_bytes());
            s.egress_mac.update(self.init_msg.as_ref().unwrap());

            // s.ingress_mac.update((mac_secret ^ remote_nonce).as_bytes());
            s.ingress_mac.update((mac_secret ^ self.nonce).as_bytes());
            s.ingress_mac.update(self.ack_msg.as_ref().unwrap());

            self.secrets = Some(s);
        }

        Ok(())
    }

    /// Encrypts auth body, used only in handshake, returns size || encrypted message
    pub fn encrypt(&self, m: BytesMut) -> BytesMut {
        let r = SecretKey::new(&mut secp256k1::rand::thread_rng());

        let s = get_shared_key(&r, &self.remote_public_key);
        // println!("e shared key: {}", S);

        let mut key = [0_u8; 32];
        kdf(s, &[], &mut key);

        let ke = H128::from_slice(&key[..16]);
        //km is actually never used, only sha256(km) is used in calculation of d
        let sha_km = sha256(&key[16..]);
        //Random initialization vector
        let iv = H128::random();

        //Calculate c, encrypt the message
        let mut c = m.to_vec();
        aes_ctr(ke, iv, &mut c);

        let total_size: u16 = u16::try_from(65 + 16 + m.len() + 32).unwrap();

        let d = mac(
            sha_km.as_bytes(),
            &[iv.as_bytes(), &c],
            &total_size.to_be_bytes(),
        );

        // encrypted message R || iv || c || d
        let mut enc_msg = BytesMut::default();

        let size = 65 + 16 + c.len() + 32;

        enc_msg.extend_from_slice(&u16::try_from(size).unwrap().to_be_bytes());

        enc_msg
            .extend_from_slice(&PublicKey::from_secret_key(SECP256K1, &r).serialize_uncompressed());
        enc_msg.extend_from_slice(iv.as_bytes());
        enc_msg.extend_from_slice(&c);
        enc_msg.extend_from_slice(d.as_bytes());

        enc_msg
    }

    /// Decrypts message received from peer (handshake or ack)
    /// msg = size (2 bytes) || body (size bytes)
    /// body = ecies_encrypted(R(65 bytes) || iv(16 bytes) || c || d(32 bytes))
    /// R - EC public key
    /// iv - random initialization vector
    /// c - AES encrypted message
    /// d - verification
    pub fn decrypt<'a>(
        &self,
        buf: &'a mut [u8],
        read_bytes: &mut u16,
    ) -> Result<&'a mut [u8], Box<dyn Error>> {
        if buf.len() > 2 {
            let (size, rest) = buf.split_at_mut(2); //size[..2], rest buf[2..]
            let payload_size = u16::from_be_bytes([size[0], size[1]]);
            *read_bytes = payload_size + 2;

            let (pub_data, rest) = rest.split_at_mut(65); //pub_data buf[2..67], rest[67..]
            let remote_pub_key = PublicKey::from_slice(pub_data)?;

            let (iv, c) = rest.split_at_mut(16); //
            let (c, d) = c.split_at_mut(payload_size as usize - (65 + 16 + 32));

            let d = H256::from_slice(&d[..32]);
            let s = get_shared_key(&self.private_key, &remote_pub_key);

            let mut key = [0_u8; 32];
            kdf(s, &[], &mut key);

            let ke = H128::from_slice(&key[0..16]);
            //km is actually never used, only sha256(km) is used in calculation of d
            let sha_km = sha256(&key[16..32]);

            let iv = H128::from_slice(iv);

            //Calculate d using encrypted data
            let calc_d = mac(
                sha_km.as_bytes(),
                &[iv.as_bytes(), c],
                &payload_size.to_be_bytes(),
            );

            aes_ctr(ke, iv, c);

            if d != calc_d {
                return Err(Box::new(ECIESError::AuthencityVerificationFailed));
            }

            return Ok(c);
        }

        Err(Box::new(ECIESError::InvalidAckData))
    }

    pub fn decode_frame_size(header: &[u8]) -> u64 {
        let mut frame_size = BigEndian::read_uint(header, 3);
        frame_size = (if frame_size % 16 == 0 {
            frame_size
        } else {
            (frame_size / 16 + 1) * 16
        }) + 16;

        frame_size
    }

    /// Reads frame data from buffer
    pub fn read_frame<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Box<dyn Error>> {
        let (header_bytes, frame) = buf.split_at_mut(32);
        let (header, mac) = header_bytes.split_at_mut(16);
        let mac = H128::from_slice(mac);

        let s = self.secrets.as_mut().unwrap();

        //validate if header MAC matches
        s.ingress_mac.update_header(header);
        let calc_mac = s.ingress_mac.digest();
        if mac != calc_mac {
            return Err(Box::new(ECIESError::InvalidFrameHeaderMac));
        }

        //decode header
        s.ingress_aes.apply_keystream(header);
        
        //Calculate frame_size
        let frame_size = Self::decode_frame_size(header);

        let (frame, _) = frame.split_at_mut(frame_size as usize);
        let (frame_data, frame_mac) = frame.split_at_mut(frame.len() - 16);
        let frame_mac = H128::from_slice(frame_mac);

        //validate if body MAC matches
        s.ingress_mac.update_body(frame_data);
        let calc_mac = s.ingress_mac.digest();
        if frame_mac != calc_mac {
            return Err(Box::new(ECIESError::InvalidFrameBodyMac));
        }

        // decrypt frame
        s.ingress_aes.apply_keystream(frame_data);

        Ok(frame_data)
    }

    /// Encode data into a frame buffer
    pub fn write_frame(&mut self, data: &[u8]) -> BytesMut {
        //Write Header
        let mut buf = [0; 8];

        BigEndian::write_uint(&mut buf, data.len() as u64, 3);

        let mut header = [0_u8; 16];
        header[0..3].copy_from_slice(&buf[0..3]);
        header[3..6].copy_from_slice(&[194, 128, 128]);

        let s = self.secrets.as_mut().unwrap();
        s.egress_aes.apply_keystream(&mut header);
        s.egress_mac.update_header(&header);

        let mac = s.egress_mac.digest();

        let mut out = BytesMut::default();
        out.reserve(32); // 16 for header, 16 for MAC
        out.extend_from_slice(&header);
        out.extend_from_slice(mac.as_bytes());
        
        //Write body, calculate len to match 16 bytes buffor chunks
        let len = if data.len() % 16 == 0 {
            data.len()
        } else {
            (data.len() / 16 + 1) * 16
        };
        let old_len = out.len();
        out.resize(old_len + len, 0);


        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        s.egress_aes.apply_keystream(encrypted);
        s.egress_mac.update_body(encrypted);
        let mac = s.egress_mac.digest();

        out.extend_from_slice(mac.as_bytes());

        out
    }

}

#[cfg(test)] 
mod test {
    use secp256k1::{SECP256K1, PublicKey};
    use crate::errors::Errors;
    use super::*;

    #[test]
    fn encrypt_decrypt_auth() -> Result<(), Box<dyn Error>> {

        let prikey1 = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let prikey2 = SecretKey::new(&mut secp256k1::rand::thread_rng());

        let public_key1 = PublicKey::from_secret_key(SECP256K1, &prikey1);
        let public_key2 = PublicKey::from_secret_key(SECP256K1, &prikey2);

        let ecies1 = Ecies::new(prikey1, public_key2)?;
        let ecies2 = Ecies::new(prikey2, public_key1)?;

        let auth_body = ecies1.get_auth_body();
        let mut enc_auth = ecies1.encrypt(auth_body.clone());

        let mut read_bytes = 0u16;

        let decrypted = ecies2.decrypt(&mut enc_auth, &mut read_bytes)?;
        let auth = &auth_body.to_vec()[..];

        if decrypted != auth {
            return Err(Box::new(Errors::EncryptionDecryptionFailed))
        }

        Ok(())
    }
}