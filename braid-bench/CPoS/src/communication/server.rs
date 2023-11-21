use core::num;
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use crate::communication::handle_prover;
use crate::communication::handle_verifier;
use crate::communication::structs::Notification;
use std::sync::mpsc::{self, Sender, Receiver};

extern crate log;
extern crate env_logger;
use log::{info, error, warn};

// pub fn start_server(isVerifier: bool, address: String) {
//     info!("Server listening on address {}", address);
//     // accept connections and process them, spawning a new thread for each one
//     thread::spawn(move || {
//         listen(isVerifier,address);
//     });
// }

// pub fn listen(isVerifier: bool, address: String) {
//     let listener = TcpListener::bind(address).unwrap();
//     for stream in listener.incoming() {
//         match stream {
//             Ok(mut stream) => {
//                 info!("New connection: {}", stream.peer_addr().unwrap());
//                 thread::spawn(move|| {
//                     handle_stream(isVerifier, &mut stream)
//                 });
//             }
//             Err(e) => {
//                 error!("Error: {}", e)
//             }
//         }
//     }
// }

// pub fn handle_stream(isVerifier: bool, stream: &mut TcpStream) {
//     let mut data = [0 as u8; 200]; // MODIFIY TO USE THE MINIMUM LENGTH BUFFER
//     match stream.read(&mut data) {
//         Ok(size) => {
//             let mut received_string = String::from("");
//             handle_message(isVerifier, &data, &stream);            
//         },
//         Err(_) => {
//             error!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
//             stream.shutdown(Shutdown::Both).unwrap();
//         }
//     }
// }

// pub fn handle_message(isVerifier: bool, msg: &[u8], stream: &TcpStream) {
//     let tag = msg[0];
//     let sender: Sender<Signal>;
//     let receiver: Receiver<Signal>;
//     (sender,receiver) = mpsc::channel();
//     if (isVerifier){    //I am a Verifier
//         if(tag == 1){
//             //handle_verifier::handle_verification(msg, stream, sender);
//         }
//         else{
//             error!("Received wrong round_id: this is a Verifier, the round_id is {}", tag)
//         }
//     }
    
//     else{               //I am a Prover
//         if(tag == 0){
//             handle_prover::handle_challenge(msg, stream, receiver);
//         }
//         else if (tag == 2){
//             handle_prover::stop_sending_proofs(sender);            
//         }
//         else{
//             error!("Received wrong round_id: this is a Prover, the round_id is {}", tag)
//         }
//     }
// }
