use std::net::{TcpStream};
use std::io::{Read, Write};
use std::str::from_utf8;
extern crate log;
extern crate env_logger;
use log::{info,error,warn};


// pub fn start_client(address: &String, msg: &[u8]) {
//     match TcpStream::connect(address) {
//         Ok(mut stream) => {
//             info!("Successfully connected to address: {}", address);
//             send_msg(&mut stream, address, msg);
//         },
//         Err(e) => {
//             error!("Failed to connect: {}", e);
//         }
//     }
//     info!("client terminated.");
// }

pub fn send_msg(mut stream: &TcpStream, msg: &[u8]) {
    match stream.write(msg) {
        Ok(_) => {info!("Message correctly sent from {} to {}", stream.local_addr().unwrap().to_string(), stream.peer_addr().unwrap().to_string())},
        Err(_) => {error!("Message not sent correctly!")},
    };
}

