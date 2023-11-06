use core::num;
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use crate::communication::handle_prover;

extern crate log;
extern crate env_logger;
use log::{info, error, warn};

pub fn start_server(isVerifier: bool) {
    
    let host = String::from("127.0.0.1");
    let port = String::from("3333");
    let address = format!("{}:{}", host, port);
    info!("Server listening on address {}", address);

    // accept connections and process them, spawning a new thread for each one
    thread::spawn(move || {
        listen(isVerifier,address);
    });
}

pub fn listen(isVerifier: bool, address: String) {
    let listener = TcpListener::bind(address).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    handle_stream(isVerifier, stream)
                });
            }
            Err(e) => {
                error!("Error: {}", e)
            }
        }
    }
}

pub fn handle_stream(isVerifier: bool, mut stream: TcpStream) {
    let mut data = [0 as u8; 200]; // using 50 byte buffer
    while match stream.read(&mut data) {
        Ok(size) => {
            // echo everything!
            let mut received_string = String::from("");
            let result = stream.read_to_string(&mut received_string);
            match stream.read_to_string(&mut received_string) { // Pass a mutable reference
                Ok(_) => {
                    println!("Received data: {}", received_string);
                    handle_message(isVerifier, received_string);
                },
                Err(e) => {
                    eprintln!("Error reading from the stream: {}", e);
                }
            }        
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

pub fn handle_message(isVerifier: bool, msg: String) {
    let msg_split: Vec<&str> = msg.split(',').collect();
    let round_id = msg_split.get(0).unwrap();
    if (isVerifier){    //I am a Verifier
        if(round_id == &"VERIFICATION"){
            
        }
        else{
            error!("Received wrong round_id: this is a Verifier, the round_id is {}", round_id)
        }
    }
    else{               //I am a Prover
        if(round_id == &"CHALLENGE"){
            handle_prover::handle_challenge(&msg_split);
        }
        else{
            error!("Received wrong round_id: this is a Prover, the round_id is {}", round_id)
        }
    }
}
