use crate::communication::{client::start_client, server::start_server, structs::Phase};


pub struct Verifier {
    address: String,
    client_address: String,
}

impl Verifier {
    fn new(address: String, client_address: String) -> Verifier {
        start_server(true, address.clone());
        return Verifier {address, client_address}
    }

    //the verifier sends a challenge composed of a seed σ, a proof of space id π, and a given byte position β.
    fn challenge(&self) {
        let phase_id = String::from ("CHALLENGE");   
        let separator = String::from(":");
        let block_id: u64 = 1;
        let init_position: u64 = 1;
        let seed = String::from("random_seed"); //to make random every call
        //eg. CHALLENGE:1:1:this_is_a_random_seed
        let msg = phase_id + &separator + &block_id.to_string() + &separator + &init_position.to_string() + &seed;  
        //send challenge to prover for the execution
        start_client(&self.client_address, &msg);
    }
    
    //get a stream of bytes as input. Recompute all the blocks in order. Check if each byte is correct according to the computed block 
    fn verify() -> bool{
        return true;
    }
}