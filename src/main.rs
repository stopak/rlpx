use secp256k1::{SecretKey};
use std::env;
use std::error::Error;
use tokio::io::AsyncWriteExt;
use tokio::{io::AsyncReadExt, net::TcpStream};

mod ecies;
mod utils;
mod errors;
mod mac;
mod rlpx;

use crate::ecies::Ecies;
use crate::errors::Errors;
use crate::rlpx::HelloMessage;
use crate::utils::get_public_key;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        let public_key = "4a3d84a401ea8a9cce6236a6f152927cceef917fc9027f09f4ac8215f26e908c907730b353caf0c7374b200da1e0e3dfef67edd9934318c73317520b1bcd2550";
        let ip = "195.201.207.37";
        let port = "30303";

        run(&ip.to_string(), &port.to_string(), &public_key.to_string()).await?;

        // println!("Invalid number of arguments! {}", args.len());
    } else {
        let s : Vec<&str> = args[1].split("://").collect();
        let s : Vec<&str> = s[1].split('@').collect();

        let public_key = s[0];
        let s : Vec<&str> = s[1].split(':').collect();
        let ip = s[0];
        let port = s[1];

        run(&ip.to_string(), &port.to_string(), &public_key.to_string()).await?;
    }
    
    Ok(())
}

async fn run(ip: &String, port: &String, key: &String) -> Result<(), Box<dyn Error>> {
    let addr = format!("{}:{}", ip, port);
    let id = hex::decode(key)?;

    let pub_k = get_public_key(&id)?;

    println!("Connecting to {}", addr);
    println!("Remote public key {}", pub_k);

    let prikey = SecretKey::new(&mut secp256k1::rand::thread_rng());
    
    let mut stream = TcpStream::connect(addr).await?;
    println!("Connected!");

    let mut ecies = Ecies::new(prikey, pub_k)?;
    let auth = ecies.get_auth_encrypted();

    if stream.write(&auth).await? == 0 {
        return Err(Box::new(Errors::SocketClosedByRemote));
    }

    let mut buf = [0_u8; 1024];
    let mut resp = stream.read(&mut buf).await?;

    if resp == 0 {
        return Err(Box::new(Errors::SocketClosedByRemote));
    }

    let mut read_bytes = 0u16; //keeps track of bytes read from buffer

    ecies.read_ack_encrypted(&mut buf, &mut read_bytes)?;
    println!("Received valid ack");

    //Send Hello Message to server
    let hello = HelloMessage {
        protocol_version: 5,
        client_version: "CustomRlpx".to_string(),
        capabilities: vec![],
        port: 0,
        id: ecies.public_key
    }.write_hello()?;
    let frame_out = ecies.write_frame(&hello);
    //Send Hello frame to server
    if stream.write(&frame_out).await? == 0 {
        return Err(Box::new(Errors::SocketClosedByRemote));
    } 

    //Read Hello Message from server

    // Check if additional data should be read from socket
    if read_bytes == resp as u16 {
        resp = stream.read(&mut buf).await?;
        if resp == 0 {
            return Err(Box::new(Errors::SocketClosedByRemote));
        }
        read_bytes = 0;
    }

    let frame = ecies.read_frame(&mut buf[read_bytes as usize..resp])?;


    let message_id: u8 = rlp::decode(&[frame[0]])?;
    match message_id {
        0 => {
            //Hello message, what was expected
            let hello = HelloMessage::read_hello(frame)?;
            println!("Received hello message:\n{}\n", hello);

            if pub_k == hello.id {
                println!("Public key verification OK!");
            } else {
                println!("Public key verification ERROR! Keys do not match {} {}", pub_k, hello.id);
            }
        },
        1 => {
            //Connection closed by peer
            println!("Received disconnect message, reason: {}", frame[1]);

            return Err(Box::new(Errors::SocketClosedByRemote))
        }
        _ => {
            return Err(Box::new(Errors::NotHandled))
        }
    }

    Ok(())
}


