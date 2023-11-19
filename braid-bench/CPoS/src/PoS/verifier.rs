use std::{str::Bytes, net::{TcpStream, Shutdown, TcpListener}, collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, sync::mpsc::{self, Sender, Receiver}, io::Read, thread};
use log::{info,error};
use rand::{Rng, seq::SliceRandom};

use crate::{communication::{client::{send_msg},structs::{Phase, Signal}, handle_prover::random_path_generator}, block_generation::utils::Utils::{INITIAL_POSITION, INITIAL_BLOCK_ID, BATCH_SIZE, NUM_BLOCK_PER_UNIT, NUM_FRAGMENTS_PER_UNIT, NUM_PROOFS_TO_VERIFY, MAX_NUM_PROOFS}};

#[derive(Debug)]
pub struct Verifier {
    address: String,
    prover_address: String,
    seed: u8
}

impl Verifier {
    pub fn new(address: String, prover_address: String) -> Verifier {
        let seed: u8 = rand::thread_rng().gen();
        //return Verifier {address, prover_address, seed}
        //let mut stream: Option<TcpStream> = None;
        let this = Self {
            address,
            prover_address,
            seed,
        };

        this
    }

    pub fn start_server(&self) {
        info!("Verifier server listening on address {}", self.address);
        
        let listener = TcpListener::bind(&self.address).unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    thread::spawn({
                        move || this.start_server()
                    });
                    info!("New connection: {}", stream.peer_addr().unwrap());
                    let mut data = [0; 128]; // Use a smaller buffer size
                    self.handle_message(self.handle_stream(&mut stream, &mut data));
                }
                Err(e) => {
                    error!("Error: {}", e)
                }
            }
        }
    }
    
    pub fn handle_stream<'a>(&self, stream: &mut TcpStream, data: &'a mut [u8]) -> &'a[u8] {
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
    
    pub fn handle_message(&self, msg: &[u8]) {
        let tag = msg[0];
        //let sender: Sender<Signal>;
        //let receiver: Receiver<Signal>;
        //(sender,receiver) = mpsc::channel();
        if(tag == 1){    //handle verification
            self.handle_verification(msg);
        }
        // else if (tag == 2){
        //     //self.stop_sending_proofs(sender);            
        // }
        else{
            error!("Received wrong round_id: this is a Prover, the round_id is {}", tag)
        }
    }

    pub fn handle_challenge(&self, msg: &[u8], receiver: mpsc::Receiver<Signal>) {
        let mut counter = 0;
        while counter < MAX_NUM_PROOFS {
            match receiver.try_recv() {  //PROBLEMA: QUA SI FERMA SEMPRE. MI SERVIREBBE UNA NOTIFICA CONTINUE A OGNI CICLO. INVECE IO VORREI UNA NOTIFICA STOP QUANDO SERVE E NEL RESTO DEL TEMPO RIMANE CONTINUE
                Ok(notification) => {
                    match notification {
                        Signal::Continue => {
                            self.create_and_send_proof_batches(msg,&receiver);
                        }
                        Signal::Stop => {
                            info!("Received Stop signal: the prover stopped sending proof batches");
                            break;
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.create_and_send_proof_batches(msg,&receiver);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    error!("The prover has been disconnected");
                    break;
                }
            }
            counter += BATCH_SIZE;
        }
    }
    
    pub fn create_and_send_proof_batches(&self, msg: &[u8], receiver: &mpsc::Receiver<Signal>) {
        let mut block_id: u32 = INITIAL_BLOCK_ID;  // Given parameter
        let mut position: u32 = INITIAL_POSITION;  //Given parameter
        let seed = msg[1];
        let proof_batch: [u8;BATCH_SIZE] = [0;BATCH_SIZE];
        for mut iteration_c in 0..proof_batch.len() {
            (block_id, position) = random_path_generator(block_id, iteration_c, position, seed);
            //proof_buffer[iteration_c] = 
        } 
        info!("Preparing batch of proofs...");
        let mut response_msg: [u8; BATCH_SIZE] = [1; BATCH_SIZE];
        response_msg[1..].copy_from_slice(&proof_batch);
        let my_slice: &[u8] = &response_msg;
        
        send_msg(&mut self.stream, &self.prover_address, &response_msg);
        info!("Batch of proofs sent to the verifier");
    }

    pub fn handle_verification(&self, msg: &[u8]) -> bool {
        return self.verify_time_challenge_bound() && self.verify_proofs(msg); //if the first is wrong, don't execute verify_proofs
    }
    
    pub fn verify_time_challenge_bound(&self) -> bool {
        return true;
    }
    
    pub fn verify_proofs(&self, msg: &[u8]) -> bool {
        let proof_batch = msg[1..].to_vec();

        let mut rng = rand::thread_rng();
        let mut shuffled_elements: Vec<u8> = msg.clone().to_vec();
        shuffled_elements.shuffle(&mut rng);
    
        for mut i in 0..NUM_PROOFS_TO_VERIFY {
            if(!self.sample_generate_verify(msg,i)){
                return false;
            };
        }
        return true;
    }
    
    pub fn sample_generate_verify(&self, msg: &[u8], i: u32) -> bool {
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

    //the verifier sends a challenge composed of a seed σ, a proof of space id π, and a given byte position β.
    pub fn challenge(&self) {
        //tag is array[0].           tag == 0 -> CHALLENGE    tag == 1 -> VERIFICATION    tag == 2 -> STOP (sending proofs)
        let tag: u8 = 0; 
        let seed: u8 = rand::thread_rng().gen_range(0..=255);
        let msg: [u8; 2] = [tag,seed];
        //send challenge to prover for the execution
        self.start_client(&self.prover_address, &msg);
    }

    //get a stream of bytes as input. Recompute all the blocks in order. Check if each byte is correct according to the computed block 
    fn verify() -> bool{
        return true;
    }   

    pub fn start_client(&mut self, address: &String, msg: &[u8]) {
        match TcpStream::connect(address) {
            Ok(mut stream) => {
                self.stream = Some(stream);
                info!("Successfully connected to address: {}", address);
                let mut option_stream = Some(stream);
                send_msg(&mut option_stream, address, msg);
            },
            Err(e) => {
                error!("Failed to connect: {}", e);
            }
        }
        info!("client terminated.");
    } 
}