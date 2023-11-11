mod communication;
mod PoS;
mod block_generation;


extern crate log;
extern crate env_logger;
use PoS::prover;
use log::{info, error};

use std::thread;
use std::time::Duration;
use crate::communication::client::start_client;
use crate::communication::server::start_server;
use crate::PoS::prover::Prover;

/*
* Possible logger levels are: Error, Warn, Info, Debug, Trace
*/
fn set_logger(){
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
}

fn main() {
    set_logger();
    //challenge: send 1(tag) + 1(seed)
    // let data: [u8, 5]= [255, 1, 7];
    let data: [u8; 3] = [255, 20, 30];

    let tag = data[0];
    let second_cell = data[1];
    let num_fragments_per_block = 1000;
    let num_block_per_unit = 100;
    let num_iterations = 8;    //IN REALTA NON MI SERVE IL NUMERO DI ITERAZIONI PERCHE CONTINUO A INVIARE FINO ALBLOCCO MANDATO DAL VERIFIER
    //let starter = Starter::new(num_fragments_per_block, num_block_per_unit, num_iterations);

    // let host_prover = String::from("127.0.0.1");
    // let port_prover = String::from("3333");
    // let address_prover = format!("{}:{}", host_prover, port_prover);

    // let host_verifier = String::from("127.0.0.1");
    // let port_verifier = String::from("4444");
    // let address_verifier = format!("{}:{}", host_verifier, port_verifier);

    // let prover = Prover::new(address_prover.clone(), address_verifier.clone());

    // let verifier = Prover::new(address_verifier, address_prover);
}
