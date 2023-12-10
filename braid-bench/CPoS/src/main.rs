mod communication;
mod PoS;
mod block_generation;
mod Merkle_Tree;

extern crate log;
extern crate env_logger;

use std::fs::{File, OpenOptions};
use std::io::{Write, SeekFrom, Seek, Read};
use std::thread;
use std::time::Duration;
use aes::Block;
use log::info; 
// use first_rust_project::Direction;


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
    let is_test = false;
    if is_test {
        let vec = vec![vec![1,2],vec![3,4],vec![5,6]];
        let flattened_vector: Vec<u8> = vec.into_iter().flatten().collect();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("test_main.bin").unwrap();
        file.write_all(&flattened_vector).unwrap();
        file.seek(SeekFrom::Start(3)).unwrap();
        let mut buffer = [0; 1];

        match file.read_exact(&mut buffer) {
            Ok(_) => {},
            Err(e) => {print!("error == {:?}", e)},
        };

        println!("buffer == {}", buffer[0]);
        let num_u64: u64 = 123456;
        println!("{:?}",num_u64.to_le_bytes());
        println!("{:?}",num_u64.to_ne_bytes());
        let num_u8 = num_u64.to_le_bytes();
        println!("converted == {}",u64::from_le_bytes(num_u8));
    }
    else{
        set_logger();
        //challenge: send 1(tag) + 1(seed)
        //let data: [u8, 5]= [255, 1, 7];
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
        thread::sleep(Duration::from_secs(7));
        //Verifier::start(address_verifier, address_prover);
        thread::sleep(Duration::from_secs(100));
    }
}
