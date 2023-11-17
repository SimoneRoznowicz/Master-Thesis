use std::{str::Bytes, net::TcpStream, collections::hash_map::DefaultHasher, hash::{Hash, Hasher}};
use rand::{Rng, seq::SliceRandom};

use crate::{communication::{client::start_client,structs::Phase}, block_generation::utils::Utils::{INITIAL_POSITION, INITIAL_BLOCK_ID, BATCH_SIZE, NUM_BLOCK_PER_UNIT, NUM_FRAGMENTS_PER_UNIT, NUM_PROOFS_TO_VERIFY}};


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
        let seed = String::from("random_seed"); //to make random every call
        //tag is array[0].           tag == 0 -> CHALLENGE    tag == 1 -> VERIFICATION    tag == 2 -> STOP (sending proofs)
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



    pub fn handle_verification(&self, msg: &[u8], stream: &TcpStream) -> bool {
        return self.verify_time_challenge_bound() && self.verify_proofs(msg, stream); //if the first is wrong, don't execute verify_proofs
    }
    
    pub fn verify_time_challenge_bound(&self) -> bool {
        return true;
    }
    
    pub fn verify_proofs(&self, msg: &[u8], stream: &TcpStream) -> bool {
        let proof_batch = msg[1..].to_vec();
        // if NUM_PROOFS_TO_VERIFY > msg.len().try_into().unwrap() {
        //     //NUM_PROOFS_TO_VERIFY = msg.len().try_into().unwrap() };
        // }
    
        let mut rng = rand::thread_rng();
        let mut shuffled_elements: Vec<u8> = msg.clone().to_vec();
        shuffled_elements.shuffle(&mut rng);
    
        for mut i in 0..NUM_PROOFS_TO_VERIFY {
            if(!self.sample_generate_verify(msg,stream,i)){
                return false;
            };
        }
        return true;
    }
    
    pub fn sample_generate_verify(&self, msg: &[u8], stream: &TcpStream, i: u32) -> bool {
        //first calculate the seed for each possible block: which means block_id and position. Store in a vector
        let mut block_id: u32 = INITIAL_BLOCK_ID;  // Given parameter
        let mut position: u32 = INITIAL_POSITION;  //Given parameter
        let seed = msg[1];
        let proof_batch: [u8;BATCH_SIZE] = [0;BATCH_SIZE];
        let mut seed_sequence: Vec<(u32, u32)> = vec![];
        for mut iteration_c in 0..proof_batch.len() {
            (block_id, position) = self.random_path_generator(block_id, iteration_c, position, seed);
            seed_sequence.push((block_id,position));
        }
    
        //generate_block(i);
        //verify_proof(i);
        return false;
    }
    
    pub fn random_path_generator(&self, id: u32, c: usize, p: u32, s: u8) -> (u32,u32) {
        let mut hasher_nxt_block = DefaultHasher::new();
        let mut hasher_nxt_pos = DefaultHasher::new();
    
        // let f =  str_to_u64(num_fragments_per_block);
        s.hash(&mut hasher_nxt_block);
        id.hash(&mut hasher_nxt_block);
        c.hash(&mut hasher_nxt_block);
        p.hash(&mut hasher_nxt_block);
        let new_id = hasher_nxt_block.finish() % NUM_BLOCK_PER_UNIT as u64;
    
        s.hash(&mut hasher_nxt_pos);
        id.hash(&mut hasher_nxt_pos);
        c.hash(&mut hasher_nxt_pos);
        p.hash(&mut hasher_nxt_pos);
        NUM_FRAGMENTS_PER_UNIT.hash(&mut hasher_nxt_pos);
        let new_p = hasher_nxt_pos.finish() % NUM_FRAGMENTS_PER_UNIT as u64;
    
        return (new_id.try_into().unwrap(), new_p.try_into().unwrap());
    }
    
}