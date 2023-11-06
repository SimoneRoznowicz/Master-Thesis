use aes::Block;

use crate::communication::{client::start_client, server::start_server, structs::Phase};
use crate::block_generation::blockgen;

use super::structs::Node;
use super::verifier;

struct Prover {
    verifier_address: String,
    list_pos: Vec<Block>
}

impl Prover {
    fn new(verifier_address: String, list_pos: Vec<Block>) -> Prover {
        start_server(false);
        return Prover { verifier_address, list_pos};
    }

    fn init(&self) {
        // assume  the verifier has the public key already

    }
    
    fn execute(){
        
    }
}
