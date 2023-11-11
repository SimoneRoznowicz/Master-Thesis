use std::net::{TcpStream};
use std::io::{Read, Write};
use std::str::from_utf8;
extern crate log;
extern crate env_logger;
use log::{info, error, warn};


pub fn start_client(address: &String, msg: &[u8]) {
    match TcpStream::connect(address) {
        Ok(mut stream) => {
            info!("Successfully connected to address: {}", address);
            let mut correctly_sent = false;
            while(!correctly_sent){
                match stream.write(msg) {
                    Ok(_) => {info!("Message correctly sent!")},
                    Err(_) => {error!("Message not sent correctly!")},
                };
            }
        },
        Err(e) => {
            error!("Failed to connect: {}", e);
        }
    }
    info!("client terminated.");
}

