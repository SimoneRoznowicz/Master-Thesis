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
    //info!("This is an informational message.");
    //error!("This is an error message.");
    let host_prover = String::from("127.0.0.1");
    let port_prover = String::from("3333");
    let address_prover = format!("{}:{}", host_prover, port_prover);

    let host_verifier = String::from("127.0.0.1");
    let port_verifier = String::from("4444");
    let address_verifier = format!("{}:{}", host_verifier, port_verifier);

    let prover = Prover::new(address_prover.clone(), address_verifier.clone());

    let verifier = Prover::new(address_verifier, address_prover);

    //start_client();
    // let sleep_duration = Duration::from_secs(5);
    // thread::sleep(sleep_duration);
}
