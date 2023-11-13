use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::TcpStream;

use aes::Block;
use rand::seq::SliceRandom;

use crate::PoS::structs::NodeType;
use super::client::start_client;
use crate::block_generation::utils::Utils::NUM_PROOFS_TO_VERIFY;
//use rand::seq::SliceRandom;


pub fn handle_verification(msg: &[u8], stream: &TcpStream) -> bool {
    return verify_time_challenge_bound() && verify_proofs(msg, stream); //if the first is wrong, don't execute verify_proofs
}

pub fn verify_time_challenge_bound() -> bool {
    return true;
}

pub fn verify_proofs(msg: &[u8], stream: &TcpStream) -> bool {
    let proof_batch = msg[1..].to_vec();
    if NUM_PROOFS_TO_VERIFY > msg.len().try_into().unwrap() {
        //NUM_PROOFS_TO_VERIFY = msg.len().try_into().unwrap();
    }

    let mut rng = rand::thread_rng();
    // let mut shuffled_elements = msg.clone();
    let mut shuffled_elements: Vec<u8> = msg.clone().to_vec();
    shuffled_elements.shuffle(&mut rng);

    for mut i in 0..NUM_PROOFS_TO_VERIFY {
        if(!sample_generate_verify(msg,stream,i)){
            return false;
        };
    }
    return true;
}

pub fn sample_generate_verify(msg: &[u8], stream: &TcpStream, i: u32) -> bool {
    //generate_block();
    //verify_proof();
    return false;
}

