use std::str::Bytes;
use rand::Rng;

use crate::communication::{client::start_client,structs::Phase};


pub struct Verifier {
    address: String,
    client_address: String,
    seed: u8
}

impl Verifier {
    fn new(address: String, client_address: String) -> Verifier {
        let seed: u8 = rand::thread_rng().gen();
        return Verifier {address, client_address, seed}
    }

    fn start_verifier(&self){
        //start_server(true, self.address.clone());
    }

    //the verifier sends a challenge composed of a seed σ, a proof of space id π, and a given byte position β.
    fn challenge(&self) {
        let phase_id = String::from ("CHALLENGE");
        let separator = String::from(":");
        let block_id: u64 = 1;
        let init_position: u64 = 1;
        let seed = String::from("random_seed"); //to make random every call
        //eg. CHALLENGE:1:1:this_is_a_random_seed
        //tag is array[0].           tag == 0 -> CHALLENGE      tag == 1 -> VERIFICATION
        let tag: u8 = 0; 
        let seed: u8 = rand::thread_rng().gen_range(0..=255);
        let msg: [u8; 2] = [tag,seed];
        //send challenge to prover for the execution
        start_client(&self.client_address, &msg);
    }

    //get a stream of bytes as input. Recompute all the blocks in order. Check if each byte is correct according to the computed block 
    fn verify() -> bool{
        return true;
    }
}