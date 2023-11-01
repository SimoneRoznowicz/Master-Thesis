use std::net::{TcpStream};
use std::io::{Read, Write};
use std::str::from_utf8;
extern crate log;
extern crate env_logger;
use log::{info, error, warn};


pub fn start_client(address: &String, message: &String) {
    match TcpStream::connect(address) {
        Ok(mut stream) => {
            info!("Successfully connected to address: {}", address);

            let msg = message.as_bytes();

            stream.write(msg).unwrap();
            info!("Message sent: {}", message);

            let mut data = [0 as u8; 6]; // using 6 byte buffer
            match stream.read_exact(&mut data) {
                Ok(_) => {
                    if &data == msg {
                        info!("Reply is ok!");
                    } else {
                        let text = from_utf8(&data).unwrap();
                        warn!("Unexpected reply: {}", text);
                    }
                },
                Err(e) => {
                    error!("Failed to receive data: {}", e);
                }
            }
        },
        Err(e) => {
            error!("Failed to connect: {}", e);
        }
    }
    info!("client terminated.");
}

