use std::{str::Bytes, net::{TcpStream, Shutdown, TcpListener}, collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, sync::mpsc::{self, Sender, Receiver}, io::Read, thread};
use log::{info,error};
use rand::{Rng, seq::SliceRandom};

use crate::{communication::{client::{send_msg},structs::{Phase, Signal}, handle_prover::random_path_generator}, block_generation::utils::Utils::{INITIAL_POSITION, INITIAL_BLOCK_ID, BATCH_SIZE, NUM_BLOCK_PER_UNIT, NUM_FRAGMENTS_PER_UNIT, NUM_PROOFS_TO_VERIFY, MAX_NUM_PROOFS}};

#[derive(Debug)]
pub struct Verifier {
    address: String,
    prover_address: String,
    seed: u8,
    stream: TcpStream
}

impl Verifier {
    pub fn new(address: String, prover_address: String) -> Verifier {
        let seed: u8 = rand::thread_rng().gen();
        //return Verifier {address, prover_address, seed}
        //let mut stream: Option<TcpStream> = None;
        let stream_option = TcpStream::connect(prover_address.clone());
        match stream_option {
            Ok(_) => {info!("Connection from verifier at {} and Prover at {} successfully created", address, prover_address)},
            Err(_) => {error!("Error in connection")},
        };
        let stream = stream_option.unwrap();
        let this = Self {
            address,
            prover_address,
            seed,
            stream
        };

        this
    }

    pub fn start_server(&self) {
        info!("Verifier server listening on address {}", self.address);
        let listener = TcpListener::bind(&self.address).unwrap(); 
        thread::spawn(move ||{
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        info!("New connection: {}", stream.peer_addr().unwrap());
                        let mut data = [0; 128]; // Use a smaller buffer size
                        handle_message(handle_stream(&mut stream, &mut data));
                    }
                    Err(e) => {
                        error!("Error: {}", e)
                    }
                }
            }
        });
    }

    pub fn handle_verification(msg: &[u8]) -> bool {
        return verify_time_challenge_bound() && verify_proofs(msg); //if the first is wrong, don't execute verify_proofs
    }
    
    //the verifier sends a challenge composed of a seed σ, a proof of space id π, and a given byte position β.
    pub fn challenge(&mut self) {
        //tag is array[0].           tag == 0 -> CHALLENGE    tag == 1 -> VERIFICATION    tag == 2 -> STOP (sending proofs)
        let tag: u8 = 0; 
        let seed: u8 = rand::thread_rng().gen_range(0..=255);
        let msg: [u8; 2] = [tag,seed];
        //send challenge to prover for the execution
        info!("Challenge being prepared by the verifier...");
        send_msg(&mut self.stream, &msg);
        //self.start_client(&self.prover_address.clone(), &msg);
    }

    //get a stream of bytes as input. Recompute all the blocks in order. Check if each byte is correct according to the computed block 
    fn verify() -> bool{
        return true;
    }   

    pub fn start_client(&mut self, address: &String, msg: &[u8]) {
        let stream = TcpStream::connect(address);
        match stream {
            Ok(mut stream) => {
                info!("Successfully connected to address: {}", address);
                send_msg(&mut stream, msg);
            },
            Err(e) => {
                error!("Failed to connect: {}", e);
            }
        }
        info!("client terminated.");
    } 
}

pub fn verify_time_challenge_bound() -> bool {
    return true;
}

pub fn verify_proofs(msg: &[u8]) -> bool {
    let proof_batch = msg[1..].to_vec();

    let mut rng = rand::thread_rng();
    let mut shuffled_elements: Vec<u8> = msg.clone().to_vec();
    shuffled_elements.shuffle(&mut rng);

    for mut i in 0..NUM_PROOFS_TO_VERIFY {
        if(!sample_generate_verify(msg,i)){
            return false;
        };
    }
    return true;
}

pub fn handle_stream<'a>(stream: &mut TcpStream, data: &'a mut [u8]) -> &'a[u8] {
    match stream.read(data) {
        Ok(size) => {
            return &data[..size];
        },
        Err(_) => {
            error!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            return &[];
        }
    }
}

pub fn sample_generate_verify(msg: &[u8], i: u32) -> bool {
    //first calculate the seed for each possible block: which means block_id and position. Store in a vector
    let mut block_id: u32 = INITIAL_BLOCK_ID;  // Given parameter
    let mut position: u32 = INITIAL_POSITION;  //Given parameter
    let seed = msg[1];
    let proof_batch: [u8;BATCH_SIZE] = [0;BATCH_SIZE];
    let mut seed_sequence: Vec<(u32, u32)> = vec![];
    for mut iteration_c in 0..proof_batch.len() {
        (block_id, position) = random_path_generator(block_id, iteration_c, position, seed);
        seed_sequence.push((block_id,position));
    }

    //generate_block(i);
    //verify_proof(i);
    return false;
}

pub fn handle_message(msg: &[u8]) {
    let tag = msg[0];
    //let sender: Sender<Signal>;
    //let receiver: Receiver<Signal>;
    //(sender,receiver) = mpsc::channel();
    if(tag == 1){    //handle verification
        //handle_verification(msg);
    }
    // else if (tag == 2){
    //     //self.stop_sending_proofs(sender);            
    // }
    else{
        error!("Received wrong round_id: this is a Prover, the round_id is {}", tag)
    }
}