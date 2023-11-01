use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
extern crate log;
extern crate env_logger;
use log::{info, error, warn};

pub fn start_server() {
    let host = String::from("127.0.0.1");
    let port = String::from("3333");
    let address = format!("{}:{}", host, port);
    info!("Server listening on address {}", address);

    // accept connections and process them, spawning a new thread for each one
    thread::spawn(|| {
        listen(address);
    });
}

pub fn listen(address: String) {
    let listener = TcpListener::bind(address).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    handle_client(stream)
                });
            }
            Err(e) => {
                error!("Error: {}", e);
            }
        }
    }
}

pub fn handle_client(mut stream: TcpStream) {
    let mut data = [0 as u8; 200]; // using 50 byte buffer
    while match stream.read(&mut data) {
        Ok(size) => {
            // echo everything!
            stream.write(&data[0..size]).unwrap();
            true
        },
        Err(_) => {
            error!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

