mod communication;
mod PoS;
mod block_generation;


extern crate log;
extern crate env_logger;

use std::thread;
use std::time::Duration;
use crate::PoS::verifier::Verifier;
//use crate::communication::server::start_server;
use crate::PoS::prover::Prover;

/*
* Possible logger levels are: Error, Warn, Info, Debug, Trace
*/
fn set_logger(){
    env_logger::builder().filter_level(log::LevelFilter::Trace).init();
}

fn main() {
    set_logger();
    //challenge: send 1(tag) + 1(seed)
    // let data: [u8, 5]= [255, 1, 7];
    let data: [u8; 3] = [255, 20, 30];

    let pub_hash = blake3::hash(b"HELLO");

    let host_prover = String::from("127.0.0.1");
    let port_prover = String::from("3333");
    let address_prover = format!("{}:{}", host_prover, port_prover);

    let host_verifier = String::from("127.0.0.1");
    let port_verifier = String::from("4444");
    let address_verifier = format!("{}:{}", host_verifier, port_verifier);

    println!("Main");
    let prover = Prover::new(address_prover.clone(), address_verifier.clone());

    let mut verifier = Verifier::new(address_verifier, address_prover);
    verifier.challenge();
    thread::sleep(Duration::from_secs(100));
}
