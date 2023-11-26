mod communication;
mod PoS;
mod block_generation;


extern crate log;
extern crate env_logger;

use std::thread;
use std::time::Duration;
use log::info;

use crate::PoS::verifier::Verifier;
//use crate::communication::server::start_server;
use crate::PoS::prover::Prover;

/*
* Possible logger levels are: Error, Warn, Info, Debug, Trace
*/
fn set_logger(){
    env_logger::builder().filter_level(log::LevelFilter::Trace).init();
}

// fn main(){
//     let mut var = 1;
//     thread::spawn(move||{
//         var = 5;
//     });
//     print!("var == {}", var);
// }

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
    //let mut prover = Prover::new(address_prover.clone(), address_verifier.clone());
    let addres_prover_clone = address_prover.clone();
    let addres_verifier_clone = address_verifier.clone();

    thread::spawn(move || {
        Prover::start(addres_prover_clone, addres_verifier_clone);
    });    
    thread::sleep(Duration::from_secs(8));

    Verifier::start(address_verifier, address_prover);
    info!("HELLO0");
    
    info!("HELLO1");
    thread::sleep(Duration::from_secs(100));
}
