use std::{error::Error, fmt::Display};

use bytes::BytesMut;
use rlp::{Decodable, Encodable, RlpStream};
use secp256k1::PublicKey;

use crate::{utils::get_public_key};

#[allow(dead_code)]
pub struct Capability {
    name: String,
    version: usize,
}

impl Decodable for Capability {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let name: String = rlp.val_at(0)?;
        let ver: usize = rlp.val_at(1)?;

        Ok(Self {
            name,
            version: ver,
        })
    }
}

impl Encodable for Capability {
    fn rlp_append(&self, rlp: &mut RlpStream) {
        rlp.begin_list(2);
        rlp.append(&self.name);
        rlp.append(&self.version);
    }
}

#[allow(dead_code)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: PublicKey,
}

impl HelloMessage {
    pub fn read_hello(frame: &[u8]) -> Result<Self, Box<dyn Error>> {
        let hello: HelloMessage = rlp::decode(&frame[1..])?;
        Ok(hello)
    }

    pub fn write_hello(&self) -> Result<BytesMut, Box<dyn Error>> {
        let mut out = BytesMut::default();

        out.extend_from_slice(&rlp::encode(&0u8)); //encode id
        out.extend_from_slice(&rlp::encode(self));

        Ok(out)
    }
}

impl Decodable for HelloMessage {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let protocol_version: usize = rlp.val_at(0)?;
        let client_version: String = rlp.val_at(1)?;
        let capabilities: Vec<Capability> = rlp.list_at(2)?;
        let port: u16 = rlp.val_at(3)?;

        let id: Vec<u8> = rlp.val_at(4)?;
        let id = get_public_key(&id)
            .map_err(|_| rlp::DecoderError::Custom("Invalid Public Key in RLP"))?;

        Ok(Self {
            protocol_version,
            client_version,
            capabilities,
            port,
            id,
        })
    }
}

impl Encodable for HelloMessage {
    fn rlp_append(&self, rlp: &mut RlpStream) {
        rlp.begin_list(5);
        rlp.append(&self.protocol_version);
        rlp.append(&self.client_version);
        rlp.append_list(&self.capabilities);
        rlp.append(&self.port);
        let buf = &self.id.serialize_uncompressed()[1..65];
        rlp.append(&buf);
    }
}

impl Display for HelloMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Protocol Version: {},\nRemote public key: {}\nClient Version: {}",
            self.protocol_version, self.id, self.client_version
        ))
    }
}

#[cfg(test)] 
mod test {
    use crate::errors::Errors;

    use super::*;
    use rlp::Rlp;

    #[test]
    fn hello_decode() -> Result<(), Box<dyn Error>> {
        let frame = hex::decode("80f88b05b2476574682f76312e31302e32352d737461626c652d36393536386335352f6c696e75782d616d6436342f676f312e31382e35d3c58365746842c58365746843c684736e61700180b8404a3d84a401ea8a9cce6236a6f152927cceef917fc9027f09f4ac8215f26e908c907730b353caf0c7374b200da1e0e3dfef67edd9934318c73317520b1bcd25500000")?;
        let rlp = Rlp::new(&frame[0..1]);

        let i : u8 = rlp.as_val()?;

        if i != 0 {
            return Err(Box::new(Errors::SocketClosedByRemote));
        }

        let _hello: HelloMessage = rlp::decode(&frame[1..])?;

        Ok(())
    }

    #[test]
    fn hello_encode_decode() -> Result<(), Box<dyn Error>> {
        let public_key = hex::decode("4a3d84a401ea8a9cce6236a6f152927cceef917fc9027f09f4ac8215f26e908c907730b353caf0c7374b200da1e0e3dfef67edd9934318c73317520b1bcd2550")?;
        let pub_k = get_public_key(&public_key)?;
        
        
        let msg = HelloMessage {
            protocol_version: 5,
            client_version: "Test Client".to_string(),
            capabilities: vec![],
            port: 0,
            id: pub_k         
        };

        let encoded_msg = rlp::encode(&msg);

        let decoded_msg: HelloMessage = rlp::decode(&encoded_msg)?;

        assert_eq!(decoded_msg.protocol_version, decoded_msg.protocol_version);
        assert_eq!(decoded_msg.client_version, decoded_msg.client_version);
        assert_eq!(decoded_msg.capabilities.len(), decoded_msg.capabilities.len());
        assert_eq!(decoded_msg.port, decoded_msg.port);
        assert_eq!(decoded_msg.id, decoded_msg.id);

        Ok(())
    }
}