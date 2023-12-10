use std::{str::Bytes, net::{TcpStream, Shutdown, TcpListener}, collections::{hash_map::DefaultHasher, HashMap}, hash::{Hash, Hasher}, sync::mpsc::{self, Sender, Receiver}, io::Read, thread::{self, Thread, JoinHandle}, vec, time::Duration};
use log::{info,error, warn, debug, trace};
use rand::{Rng, seq::SliceRandom};
use talk::crypto::primitives::hash::HASH_LENGTH;

use crate::{communication::{client::{send_msg},structs::{Notification, Fairness, Verification_Status, Failure_Reason, Time_Verification_Status}, handle_prover::random_path_generator}, block_generation::{utils::Utils::{INITIAL_POSITION, INITIAL_BLOCK_ID, BATCH_SIZE, NUM_BLOCK_GROUPS_PER_UNIT, NUM_FRAGMENTS_PER_UNIT, NUM_PROOFS_TO_VERIFY, MAX_NUM_PROOFS, CHECKING_FACTOR}, encoder::generate_block_group, blockgen::BlockGroup}, Merkle_Tree::{mpt::{MerkleTree, from_bytes_to_proof}, structs::{Proof, Id}, client_verify::get_root_hash}};

use super::structs::NotifyNode;

pub struct Verifier {
    address: String,
    prover_address: String,
    seed: u8,
    stream: TcpStream,
    proofs: Vec<u8>,
    is_fair: bool,
    is_terminated: bool,
    seed_map: HashMap<u32,u32>,
    hash_root: [u8; HASH_LENGTH],
    status: (Verification_Status,Fairness)
}

impl Verifier {

    pub fn start(address: String, prover_address: String){
        //channel to allow the verifier threads communicate with the main thread
        let sender: Sender<NotifyNode>;
        let receiver: Receiver<NotifyNode>;
        (sender,receiver) = mpsc::channel();

        let seed = rand::thread_rng().gen();
        let mut verifier = Verifier::new(address, prover_address, sender.clone(), seed);

        info!("Verifier starting main_handler()");
        verifier.main_handler(&receiver,&sender);
    }

    fn new(address: String, prover_address: String, sender: Sender<NotifyNode>, seed: u8) -> Verifier {

        //return Verifier {address, prover_address, seed}
        //let mut stream: Option<TcpStream> = None;
        let stream_option = TcpStream::connect(prover_address.clone());
        match &stream_option {
            Ok(stream) => {info!("\nConnection from verifier at {} and Prover at {} successfully created ",&stream.local_addr().unwrap(),&stream.peer_addr().unwrap())},
            Err(_) => {error!("Error in connection")},
        };
        let stream = stream_option.unwrap();
        let mut proofs: Vec<u8> = Vec::new();
        let mut status = (Verification_Status::Executing,Fairness::Undecided);
        let is_fair = true;
        let is_terminated = false;
        let mut seed_map: HashMap<u32, u32> = HashMap::new();
        let hash:[u8; HASH_LENGTH] = Default::default();
        let mut this = Self {
            address,
            prover_address,
            seed,
            stream,
            proofs,
            is_fair,
            is_terminated,
            seed_map,
            hash_root: hash,
            status,
        };
        this.start_server(sender);
        this
    }

    fn start_server(&mut self, sender: Sender<NotifyNode>) {
        let mut stream_clone = self.stream.try_clone().unwrap();
        thread::spawn(move || {
            loop{
                let sender_clone = sender.clone();
                let mut data = [0; 128]; // Use a smaller buffer size
                handle_message(handle_stream(&mut stream_clone, &mut data), sender_clone);
            }
        });
    }

    fn main_handler(&mut self, receiver: &Receiver<NotifyNode>, sender: &Sender<NotifyNode>){
        let mut is_to_challenge = true;
        let mut is_to_verify = false;
        let mut is_stopped = false;
        loop {
            if is_to_challenge {
                is_to_challenge = false;
                info!("Verifier prepares the challenge");
                self.challenge();
            }
            info!("Before Recv");
            match receiver.recv() {
                Ok(notify_node) => {
                    match notify_node.notification {
                        Notification::Verification_Time => {
                            if is_to_verify {
                                let stream_clone = self.stream.try_clone().unwrap();
                                let sender_clone = sender.clone();
                                let mut proofs_clone = self.proofs.clone();
                                Some(thread::spawn(move || {
                                    if is_stopped == false {
                                        info!("Verifiier received notification: Verification");
                                        handle_verification(&stream_clone, &notify_node.buff, &mut proofs_clone, &sender_clone);
                                    }
                                    else{
                                        info!("Received notification Verification but this is not required at this point");
                                    }
                                }));
                            }
                        },
                        Notification::Verification_Correctness => {
                            //is_to_verify = false;
                            //let seed_clone = self.seed.clone();
                            //let stream_clone = self.stream.try_clone().unwrap();
                            self.verify_correctness_proofs(&notify_node.buff);
                        },
                        Notification::Handle_Inclusion_Proof => {
                            let sender_clone = sender.clone();
                            let tag = notify_node.buff[0];
                            // if(tag == 4) {  //This is the first Inclusion proof received:
                            //     self.hash_root.copy_from_slice(&notify_node.buff[1..1+HASH_LENGTH]);
                            //     let root_hash = self.hash_root.clone();
                            //     let mut buff_without_root_hash: Vec<u8> = Vec::new();
                            //     buff_without_root_hash.push(5);
                            //     buff_without_root_hash.extend_from_slice(&notify_node.buff[1+HASH_LENGTH..]);
                            //     thread::spawn(move || {
                            //         handle_inclusion_proof(&buff_without_root_hash, &sender_clone, &root_hash);
                            //     });
                            // }
                            // else {  //tag == 5
                                let root_hash = self.hash_root.clone();
                                thread::spawn(move || {
                                    handle_inclusion_proof(&notify_node.buff, &sender_clone, &root_hash);
                                });
                            // }
                        }
                        Notification::Update => {
                            if !self.is_terminated {
                                if notify_node.buff[0] == 0 {
                                    self.proofs.extend(notify_node.buff);
                                } else {
                                    if(notify_node.buff[1] == 1){
                                        info!("A wrong inclusion proof was found: terminate immediately");
                                        self.is_terminated = true;
                                        self.is_fair = false;
                                        let terminate_vector = vec![2];  //Unfair(Time Reason)
                                        sender.send(NotifyNode {buff: terminate_vector, notification: Notification::Terminate});
                                    }
                                }
                            }
                        },
                        Notification::Terminate => {
                            is_to_verify = false;
                            let is_fair: Fairness;
                            //0-->Fair; 1-->Unfair(Time Reason); 2-->Unfair(Correctness Reason)
                            if (notify_node.buff[0] == 0) {is_fair = Fairness::Fair}
                            else if (notify_node.buff[0] == 1) {is_fair = Fairness::Unfair(Failure_Reason::Time)}
                            else {is_fair = Fairness::Unfair(Failure_Reason::Correctness)}
                            self.status = (Verification_Status::Terminated, is_fair);
                            info!("\n***************************\nResult of the Challenge:{:?}\n***************************", self.status);
                            //if needed you can reset the status here
                            break;
                        }
                        _ => {error!("Unexpected Notification of type {:?}", notify_node.notification)}
                    }
                },
                Err(e) => {warn!("Error == {}", e)}
            }

        }
        thread::sleep(Duration::from_secs(5));
    }

    //the verifier sends a challenge composed of a seed σ, a proof of space id π, and a given byte position β.
    pub fn challenge(&mut self) {
        //tag is msg[0].           tag == 0 -> CHALLENGE    tag == 1 -> VERIFICATION    tag == 2 -> STOP (sending proofs)
        //seed is msg[1]
        let tag: u8 = 0;
        let seed: u8 = rand::thread_rng().gen_range(0..=255);
        let msg: [u8; 2] = [tag,seed];
        //send challenge to prover for the execution
        send_msg(&mut self.stream, &msg);
        info!("Challenge sent to the prover...");
    }

    //Verify some of the proofs: generate the seed correspondent to all the proofs.

    //[0,*1,2,*3,4,5,*6,*7,8,*9]
    //[1,2,3,4,5]
    //update eg.  i = i + (1/3)*10
    //update i = i + (% of samples I want to test) * (length of proof vector)
    fn verify_correctness_proofs(&mut self, msg: &[u8]) -> bool {
        let mut block_id: u32 = INITIAL_BLOCK_ID;  // Given parameter
        let mut position: u32 = INITIAL_POSITION;  //Given parameter
        let seed = msg[1];  //sbagliato lo devi prendere da self il seed
        let mut seed_sequence: Vec<(u32, u32)> = vec![];
        let mut seed_map: HashMap<u32, u32> = HashMap::new();

        for mut iteration_c in 0..msg.len() {
            (block_id, position) = random_path_generator(block_id, iteration_c, position, seed);
            seed_sequence.push((block_id,position));
            seed_map.insert(block_id, position);
            //dovrebbe essere una map con key u8 ovvero block_id e value u8 ovvero la position del byte nel block
        }
        self.seed_map = seed_map;

        let mut i: u32 = 0;
        let proofs_len = msg.len() as u32;
        let avg_step = (CHECKING_FACTOR * proofs_len as f32).round() as i32;
        let random_step = rand::thread_rng().gen_range(-avg_step+1..=avg_step-1);

        let mut all_verified_indexes: Vec<u8> = Vec::new();
        all_verified_indexes.push(3);   //tag == 3 --> Send request to have a Merkle Tree proof for a specific u8 proof
        while(i<msg.len() as u32){
            if !check_block(seed_sequence[i as usize].0,seed_sequence[i as usize].1){
                return false;
            }

            //send request Merkle Tree for each of the proof: send tag 3 followed by the indexes
            let bytes_i = i.to_le_bytes();
            all_verified_indexes.extend(bytes_i);
            i = i + ((avg_step + random_step) as u32);
        }

        send_msg(&self.stream, &all_verified_indexes);
        return true;
    }
}


fn send_stop_msg(stream: &TcpStream){
    info!("Sending Stop message to the prover");
    let msg_to_send: [u8; 1] = [2];
    send_msg(stream, &msg_to_send[..]);
}

fn handle_verification(stream: &TcpStream, new_proofs: &[u8], proofs: &mut Vec<u8>, sender: &Sender<NotifyNode>) {
    //note that new_proofs e proofs hanno gia rimosso il primo byte del tag
    //Update vector of proofs
    proofs.extend(new_proofs);
    let mut update_new_proofs = Vec::new();
    update_new_proofs.push(0);
    update_new_proofs.extend_from_slice(new_proofs);
    sender.send(NotifyNode {buff: update_new_proofs, notification: Notification::Update}).unwrap();
    //verify_time_challenge_bound() should return three cases:
    //Still not verified
    //Verified Correct (we can proceed to verify the correctness of the proofs)
    //Verified Not Correct
    match verify_time_challenge_bound() {
        Time_Verification_Status::Correct => {
            send_stop_msg(stream);
            info!("Starting correctness verifications of the proofs");
            match sender.send(NotifyNode {buff: proofs.to_vec(), notification: Notification::Verification_Correctness}) {
                Ok(_) => {},
                Err(e) => {warn!("{:?} sent through the channel didn't reach the receiver\nReason: {}",Notification::Verification_Correctness,e.to_string())},
            };
        },
        Time_Verification_Status::Incorrect => {
            send_stop_msg(stream);
            info!("Terminating Verification: the time bound was not satisfied by the prover");
            let terminate_vector = vec![1];  //Unfair(Time Reason)
            match sender.send(NotifyNode {buff: terminate_vector, notification: Notification::Terminate}) {
                Ok(_) => {},
                Err(e) => {warn!("{:?} sent through the channel didn't reach the receiver\nReason: {}",Notification::Terminate,e.to_string())},
            };
        },
        Time_Verification_Status::Insufficient_Proofs => {/*Do nothing*/}
    }
}

fn handle_inclusion_proof(bytes_proof: &[u8], sender: &Sender<NotifyNode>, root_hash_bytes: &[u8;32]) {
    let proof = from_bytes_to_proof(bytes_proof.to_vec());
    let byte_value: u8 = 0;
    let byte_position: u8 = 0;
    let hash_retrieved = get_root_hash::<u8,u8>(proof, byte_value, Id::<u8>::new(byte_position));
    let stored_root_hash = root_hash_bytes;  //FAKE
    let mut correctness_flag = 1;  //Default: false
    if(hash_retrieved.to_bytes() == *stored_root_hash){  //convert to byte array the hash_retrieved. Then compare.
        correctness_flag = 0;
    }
    let mut update_new_proofs = Vec::new();
    update_new_proofs.push(1);
    update_new_proofs.push(correctness_flag);

    sender.send(NotifyNode {buff: update_new_proofs, notification: Notification::Update}).unwrap();
}

fn verify_time_challenge_bound() -> Time_Verification_Status{
    return Time_Verification_Status::Incorrect;
}

fn check_block(block_id: u32, pos_in_block: u32) -> bool{
    //TODO
    let block = generate_block_group(block_id.try_into().unwrap());
    return true;
}

fn sample_generate_verify(msg: &[u8], i: u32) -> bool {
    let mut block_id: u32 = INITIAL_BLOCK_ID;  // Given parameter
    let mut position: u32 = INITIAL_POSITION;  //Given parameter
    let seed = msg[1];  //sbagliato lo devi prendere da self il seed

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

fn handle_stream<'a>(stream: &mut TcpStream, data: &'a mut [u8]) -> &'a[u8] {
    match stream.read(data) {
        Ok(size) => {
            trace!("reading data in handle_stream in verifier");
            return &data[..size];
        },
        Err(_) => {
            error!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            return &[];
        }
    }
}

fn handle_message(msg: &[u8], sender: Sender<NotifyNode>) {
    let tag = msg[0];
    debug!("Tag in verifier is == {}", msg[0]);
    if tag == 1 {
        debug!("Thread in verifier notified of the new buffer. Send for verification to the main thread");
        match sender.send(NotifyNode{ buff: msg[1..].to_vec(), notification: Notification::Verification_Time }) {
            Ok(_) => {debug!("good send to main")},
            Err(e) => {debug!("error first send channel == {}",e)},
        };
    }
    else if tag == 4 || tag == 5 {
        info!("Handle Verification of the first Inclusion Proof");
        match sender.send(NotifyNode{ buff: msg[1..].to_vec(), notification: Notification::Handle_Inclusion_Proof }) {
            Ok(_) => {debug!("good send to main")},
            Err(e) => {debug!("error first send channel == {}",e)},
        };
    }
    else{
        error!("In verifier the tag is NOT 1: the tag is {}", tag)
    }
}


