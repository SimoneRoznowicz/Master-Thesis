use aes::Block;

use crate::communication::{client::start_client, server::start_server, structs::Phase};
use crate::block_generation::blockgen;

use super::structs::Node;
use super::verifier;

pub struct Prover {
    address: String,
    verifier_address: String,
    //list_pos: Vec<Block>
}

impl Prover {
    pub fn new(address: String, verifier_address: String/*, list_pos: Vec<Block>*/) -> Prover {
        start_server(false, address.clone());
        return Prover { address, verifier_address};
    }

    pub fn init(&self) {
        // assume  the verifier has the public key already

    }
    
    pub fn execute(){
        
    }
}
