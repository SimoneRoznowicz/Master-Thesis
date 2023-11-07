use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::TcpStream;

use crate::PoS::structs::NodeType;
use super::client::start_client;

pub fn handle_verification(msg_split: &Vec<&str>, stream: &TcpStream) {
    let mut block_id = str_to_u64(*msg_split.get(1).unwrap());
    let mut init_position = str_to_u64(*msg_split.get(2).unwrap());
    let num_iterations = *msg_split.get(4).unwrap();
    let num_block_per_unit = str_to_u64("10");  //THIS IS TO BE TAKEN FROM THE BLOCK. 10 IS FAKE
    for mut iteration_c in 0..str_to_u64(num_iterations){
        (block_id, init_position) = random_path_generator(block_id, iteration_c, init_position, num_block_per_unit);
    }
}

fn str_to_u64(s: &str) -> u64 {
    match s.parse() {
        Ok(s) => s,
        Err(_) => panic!(),
    }
}

pub fn random_path_generator(id: u64, c: u64, p: u64, num_block_per_unit: u64) -> (u64,u64) {
    let num_fragments_per_block = "100";    //TEMPORARY VALUE: TO RETRIEVE FROM THE BLOCK GENERATOR

    let mut hasher_nxt_block = DefaultHasher::new();
    let mut hasher_nxt_pos = DefaultHasher::new();

    let f =  str_to_u64(num_fragments_per_block);

    id.hash(&mut hasher_nxt_block);
    c.hash(&mut hasher_nxt_block);
    p.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % num_block_per_unit;

    id.hash(&mut hasher_nxt_pos);
    c.hash(&mut hasher_nxt_pos);
    p.hash(&mut hasher_nxt_pos);
    f.hash(&mut hasher_nxt_pos);

    let new_p = hasher_nxt_pos.finish() % f;
    return (new_id, new_p);
}


