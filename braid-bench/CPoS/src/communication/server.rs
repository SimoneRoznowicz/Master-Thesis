use core::num;
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

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
        if(round_id == &"EXECUTION"){
        }
        else{
            error!("Received wrong round_id: this is a Verifier, the round_id is {}", round_id)
        }
    }
    else{               //I am a Prover
        if(round_id == &"CHALLENGE"){
            handle_challenge(&msg_split);
        }
        else{
            error!("Received wrong round_id: this is a Prover, the round_id is {}", round_id)
        }
    }
}

pub fn handle_challenge(msg_split: &Vec<&str>) {
    let block_id = msg_split.get(1).unwrap();
    let init_position = msg_split.get(2).unwrap();
    let seed = msg_split.get(3).unwrap();
    let num_iterations = msg_split.get(4).unwrap();
    let num_block_per_unit = &"10";  //THIS IS TO BE TAKEN FROM THE BLOCK. 10 IS FAKE
    for iteration_c in 0..str_to_u64(num_iterations).unwrap() {
        let string_iteration = iteration_c.to_string();
        let str_iteration = &string_iteration.as_str();
        // let str_iteration = string_iteration.as_str();
        random_hash(block_id, str_iteration, init_position, num_block_per_unit);        
    }
}
fn str_to_u64(s: &str) -> Result<u64, std::num::ParseIntError> {
    s.parse()
}

pub fn random_hash(id: &&str, c: &&str, p: &&str, num_block_per_unit: &&str) -> u64{
    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    c.hash(&mut hasher);
    p.hash(&mut hasher);
    return hasher.finish() % 10;
    //dovrebbe restituire una tupla: next block id and next position to verifiy (u64) in the next block. Per ora restituisce solo next block id  
}
