use aes::cipher::Counter;
use log::{debug, error, info, trace, warn};
use rand::{Rng};
use serde_json::error;
use std::{
    collections::{HashMap},
    io::Read,
    net::{Shutdown, TcpStream},
    sync::mpsc::{self, Receiver, Sender},
    thread::{self},
    time::Duration,
    vec,
};
use talk::crypto::primitives::hash::HASH_LENGTH;

use crate::{
    block_generation::{
        encoder::generate_block_group,
        utils::Utils::{
            BATCH_SIZE, VERIFIABLE_RATIO, HASH_BYTES_LEN, INITIAL_BLOCK_ID, INITIAL_POSITION, NUM_BYTES_PER_BLOCK_ID,
            NUM_BYTES_PER_POSITION,
        }, blockgen::GROUP_SIZE,
    },
    communication::{
        client::send_msg,
        handle_prover::random_path_generator,
        structs::{
            Failure_Reason, Fairness, Notification, Time_Verification_Status, Verification_Status,
        },
    },
    Merkle_Tree::{
        client_verify::get_root_hash,
        structs::{Id},
    },
};

use super::{structs::NotifyNode, utils::from_bytes_to_proof};

pub struct Verifier {
    address: String,
    prover_address: String,
    seed: u8,
    stream: TcpStream,
    proofs: Vec<u8>,
    is_fair: bool,
    is_terminated: bool,
    mapping_bytes: HashMap<(u32, u32), (u8, bool)>, // k: (block_id,position) v: (byte_value, inclusion_proof_already_verified)
    //hash_root: [u8; HASH_LENGTH],
    status: (Verification_Status, Fairness),
    counter: u8,  //FAKE TO BE ROMVED
}

impl Verifier {
    pub fn start(address: String, prover_address: String) {
        //channel to allow the verifier threads communicate with the main thread
        let sender: Sender<NotifyNode>;
        let receiver: Receiver<NotifyNode>;
        (sender, receiver) = mpsc::channel();

        let seed = rand::thread_rng().gen();
        debug!("SEED INITIALLY == {}", seed);

        let mut verifier = Verifier::new(address, prover_address, sender.clone(), seed);

        info!("Verifier starting main_handler()");
        verifier.main_handler(&receiver, &sender);
    }

    fn new(
        address: String,
        prover_address: String,
        sender: Sender<NotifyNode>,
        seed: u8,
    ) -> Verifier {
        //return Verifier {address, prover_address, seed}
        // let mut stream: Option<TcpStream> = None;

        // let stream_option = TcpStream::connect(prover_address.clone());
        // match &stream_option {
        //     Ok(stream) => {
        //         info!(
        //             "\nConnection from verifier at {} and Prover at {} successfully created ",
        //             &stream.local_addr().unwrap(),
        //             &stream.peer_addr().unwrap()
        //         )
        //     }
        //     Err(e) => {
        //         error!("Error in connection: {}", e)
        //     }
        // };
        let mut stream_option: Result<TcpStream, std::io::Error>;
        loop {
            stream_option = TcpStream::connect(prover_address.clone());
            match stream_option {
                Ok(_) => {
                    info!("Connection Successful!");
                    break;
                },
                Err(e) => {
                    warn!("Connection was not possible. Retry in 2 seconds...");
                    thread::sleep(Duration::from_secs(2));
                },
            }
        }
    
        let stream = stream_option.unwrap();
        let proofs: Vec<u8> = Vec::new();
        let status = (Verification_Status::Executing, Fairness::Undecided);
        let is_fair = true;
        let is_terminated = false;
        let seed_map: HashMap<(u32, u32), (u8, bool)> = HashMap::new();
        //let hash:[u8; HASH_LENGTH] = Default::default();
        let mut counter = 0;
        let mut this = Self {
            address,
            prover_address,
            seed,
            stream,
            proofs,
            is_fair,
            is_terminated,
            mapping_bytes: seed_map,
            //hash_root: hash,
            status,
            counter,
        };
        this.start_server(sender);
        this
    }

    fn start_server(&mut self, sender: Sender<NotifyNode>) {
        let mut stream_clone = self.stream.try_clone().unwrap();
        thread::spawn(move || {
            loop {
                let sender_clone = sender.clone();
                let mut data = [0; 128]; // Use a smaller buffer size
                handle_message(handle_stream(&mut stream_clone, &mut data), sender_clone);
            }
        });
    }

    fn main_handler(&mut self, receiver: &Receiver<NotifyNode>, sender: &Sender<NotifyNode>) {
        let mut is_to_challenge = true;
        let mut is_to_verify = true;
        let is_stopped = false;
        loop {
            if is_to_challenge {
                is_to_challenge = false;
                info!("Verifier prepares the challenge");
                self.challenge();
            }
            match receiver.recv() {
                Ok(mut notify_node) => {
                    match notify_node.notification {
                        Notification::Verification_Time => {
                            if is_to_verify {
                                let stream_clone = self.stream.try_clone().unwrap();
                                let sender_clone = sender.clone();
                                let mut proofs_clone = self.proofs.clone();
                                self.counter += 1;
                                let mut counter_clone = self.counter;
                                Some(thread::spawn(move || {
                                    if is_stopped == false {
                                        info!("Verifier received notification: Verification");
                                        handle_verification(
                                            &stream_clone,
                                            &notify_node.buff,
                                            &mut proofs_clone,
                                            &sender_clone,
                                            counter_clone,
                                        );
                                    } else {
                                        info!("Received notification Verification but this is not required at this point");
                                    }
                                }));
                            }
                        }
                        Notification::Verification_Correctness => {
                            //is_to_verify = false;
                            //let seed_clone = self.seed.clone();
                            //let stream_clone = self.stream.try_clone().unwrap();
                            self.verify_correctness_proofs(&notify_node.buff);
                        }
                        Notification::Handle_Inclusion_Proof => {
                            info!("Handle_Inclusion_Proof started");
                            let sender_clone = sender.clone();
                            thread::spawn(move || {
                                handle_inclusion_proof(
                                    //&notify_node.buff[1 + HASH_LENGTH..],
                                    &notify_node.buff,
                                    &sender_clone,
                                );
                            });
                        }
                        Notification::Update => {
                            if !self.is_terminated {
                                if notify_node.buff[0] == 0 {
                                    self.proofs.extend_from_slice(&mut notify_node.buff[1..]);
                                } else {
                                    if notify_node.buff[1] == 1 {
                                        info!("A wrong inclusion proof was found: terminate immediately");
                                        self.is_terminated = true;
                                        self.is_fair = false;
                                        let terminate_vector = vec![2]; //Unfair(Time Reason)
                                        sender.send(NotifyNode {
                                            buff: terminate_vector,
                                            notification: Notification::Terminate,
                                        }).unwrap();
                                    }
                                }
                            }
                        }
                        Notification::Terminate => {
                            is_to_verify = false;
                            let is_fair: Fairness;
                            //0-->Fair; 1-->Unfair(Time Reason); 2-->Unfair(Correctness Reason)
                            if notify_node.buff[0] == 0 {
                                is_fair = Fairness::Fair
                            } else if notify_node.buff[0] == 1 {
                                is_fair = Fairness::Unfair(Failure_Reason::Time)
                            } else {
                                is_fair = Fairness::Unfair(Failure_Reason::Correctness)
                            }
                            self.status = (Verification_Status::Terminated, is_fair);
                            info!("\n***************************\nResult of the Challenge:{:?}\n***************************", self.status);
                            break;
                        }
                        _ => {
                            error!(
                                "Unexpected Notification of type {:?}",
                                notify_node.notification
                            )
                        }
                    }
                }
                Err(e) => {
                    warn!("Error == {}", e)
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    }

    //the verifier sends a challenge composed of a seed σ, a proof of space id π, and a given byte position β.
    pub fn challenge(&mut self) {
        //tag is msg[0].           tag == 0 -> CHALLENGE    tag == 1 -> VERIFICATION    tag == 2 -> STOP (sending proofs)
        //seed is msg[1]
        let tag: u8 = 0;
        let msg: [u8; 2] = [tag, self.seed];
        //send challenge to prover for the execution
        send_msg(&mut self.stream, &msg);
        info!("Challenge sent to the prover...");
    }

    //V: Iteration: 0, block_id = 3, position = 195687, value = 192
    //P: Iteration: 0, block_id = 3, position = 195687, value = 192
    //Verify some of the proofs: generate the seed correspondent to all the proofs.
    //[0,*1,2,*3,4,5,*6,*7,8,*9]
    //[1,2,3,4,5]
    //update eg.  i = i + (1/3)*10
    //update i = i + (% of samples I want to test) * (length of proof vector)
    fn verify_correctness_proofs(&mut self, msg: &[u8]) -> bool {
        info!("Starting verify_correctness_proofs ***");
        let mut block_id: u32 = INITIAL_BLOCK_ID;
        let mut position: u32 = INITIAL_POSITION;
        let mut block_ids_pos: Vec<(u32, u32)> = vec![];

        for iteration in 0..msg.len() {
            (block_id, position, self.seed) = random_path_generator(self.seed, iteration as u8);
            block_ids_pos.push((block_id, position));
            //dovrebbe essere una map con key u8 ovvero block_id e value u8 ovvero la position del byte nel block
        }


        let proofs_len = msg.len() as u32;
        let mut verfiable_ratio = VERIFIABLE_RATIO;
        if VERIFIABLE_RATIO == 0.0 {
            warn!("VERIFIABLE_RATIO was set to 0: it was reset to 0.5");
            verfiable_ratio = 0.5;
        }
        let avg_step = (1.0/verfiable_ratio).floor() as i32;
        let mut i: i32 = -avg_step;
        let mut random_step = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
        // info!("Average Step == {} + random Step == {}", avg_step, random_step);

        let mut verified_blocks_and_positions: Vec<u8> = Vec::new();
        i = (i + ((avg_step + random_step) as i32)).abs();
        random_step = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);

        info!("i == {}, Average Step == {} + random Step == {}",i, avg_step, random_step);

        verified_blocks_and_positions.push(3); //tag == 3 --> Send request to have a Merkle Tree proof for a specific u8 proof
        while i < msg.len() as i32 {
            self.mapping_bytes.insert((block_id, position), (0, false));
            warn!("V: Iteration: {}, block_id = {}, position = {}, value = {}", i, block_ids_pos[i as usize].0, block_ids_pos[i as usize].1, msg[i as usize]);
            warn!("Indexxx == {}, msg before check == {:?}", i, msg);

            if !self.check_byte_value(
                block_ids_pos[i as usize].0,
                block_ids_pos[i as usize].1,
                msg[i as usize],
            ) {
                warn!("Found incorrect byte value while checking");
                return false;
            }
            //send request Merkle Tree for each of the proof: send tag 3 followed by the indexes (block_ids), followed by the positions
            let block_id = i.to_le_bytes();
            let position = block_ids_pos[i as usize].1.to_le_bytes();
            verified_blocks_and_positions.extend(block_id);
            verified_blocks_and_positions.extend(position);
            i = i + ((avg_step + random_step) as i32);
            info!("Average Step == {} + random Step == {}", avg_step, random_step);
            random_step = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
        }
        info!("Successful Correctness Verification");
        send_msg(&self.stream, &verified_blocks_and_positions);
        return true;
    }

    //[[0,1,2,3],[4,5,6,7],[8,9,10,11],[12,13,14,15]]
    //blockid 10
    //10 / 4  = 2
    //8 / 4  = 2
    //10 % 4 == 2
    fn check_byte_value(&mut self, block_id: u32, pos_in_block: u32, byte_received: u8) -> bool {
        let block_group: Vec<[u64; GROUP_SIZE]> = generate_block_group((block_id / GROUP_SIZE as u32).try_into().unwrap());
        // warn!("generate_block_group with input == {}", block_id / GROUP_SIZE as u32);
        //block from [0 to 3] within the blockgroup
        //let block_num_in_group = pos_in_block % 4;
        let selected_arr: [u64; GROUP_SIZE] = block_group[(pos_in_block/8) as usize]; //4 cells made of 8 bytes each

        let mut array_u8: [u8; 8*GROUP_SIZE] = [0;8*GROUP_SIZE];

        for (i, &element) in selected_arr.iter().enumerate() {
            let bytes = element.to_le_bytes();
            array_u8[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        //PROVA A TENERE QUA SOTTO MODULO 8 E NON 32 ANCHE CON SIZE 4
        //let byte_value   = array_u8[(pos_in_block % 8) as usize];
        // let byte_value_2 = array_u8[8 + (pos_in_block % 8) as usize];
        // let byte_value_3 = array_u8[16 + (pos_in_block % 8) as usize];
        // let byte_value_4 = array_u8[24 + (pos_in_block % 8) as usize];
        let byte_value = array_u8[(block_id % GROUP_SIZE as u32) as usize*8 + (pos_in_block % 8) as usize];



        // let partblock = block_group[(block_id % 4) as usize];
        // SBAGLIATOOOOOOOO SERVE POSITION NELL INDICE DEL BLOCK SOPRA CREDO
        // let fragment = partblock[(pos_in_block/4) as usize];
        // let byte_value = fragment.to_le_bytes()[(pos_in_block % 4) as usize];
        
        //warn!("byte_arr_32 == {:?}",selected_arr);
        //warn!("byte_arr == {:?}",array_u8);
        //warn!("byte_val == {}, byte_val2 == {}, byte_val3 == {}, byte_val4 == {}", byte_value, byte_value_2, byte_value_3, byte_value_4);

        warn!("byte_value_real == {} and byte_received == {}",byte_value,byte_received);

        self.mapping_bytes
        .insert((block_id, pos_in_block), (byte_value, false));

        return byte_value == byte_received;
    }
}

fn send_stop_msg(stream: &TcpStream) {
    let msg_to_send: [u8; 1] = [2];
    send_msg(stream, &msg_to_send[..]);
}

fn send_update_notification(new_proofs: &[u8], sender: &Sender<NotifyNode>) {
    let mut update_new_proofs = Vec::new();
    update_new_proofs.push(0);
    update_new_proofs.extend_from_slice(new_proofs);
    sender
        .send(NotifyNode {
            buff: update_new_proofs,
            notification: Notification::Update,
        })
        .unwrap();
}

fn handle_verification(
    stream: &TcpStream,
    new_proofs: &[u8],
    proofs: &mut Vec<u8>,
    sender: &Sender<NotifyNode>,
    counter: u8,  //FAKE TO REMOVE AFTER TIME CHECK IMPLEMENTATION
) {
    //note that new_proofs e proofs hanno gia rimosso il primo byte del tag
    //Update vector of proofs
    // error!("Proofs byte before extending: {:?}", proofs);
    proofs.extend(new_proofs);
    // error!("Proofs byte after extending: {:?}", proofs);

    send_update_notification(new_proofs, sender);
    //verify_time_challenge_bound() should return three cases:
    //Still not verified
    //Verified Correct (we can proceed to verify the correctness of the proofs)
    //Verified Not Correct
    match verify_time_challenge_bound(counter) {
        Time_Verification_Status::Correct => {
            warn!("--> Time_Verification_Status::Correct");
            send_stop_msg(stream);
            match sender.send(NotifyNode {
                buff: proofs.to_vec(),
                notification: Notification::Verification_Correctness,
            }) {
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        "{:?} sent through the channel didn't reach the receiver\nReason: {}",
                        Notification::Verification_Correctness,
                        e.to_string()
                    )
                }
            };
        }
        Time_Verification_Status::Incorrect => {
            warn!("--> Time_Verification_Status::Incorrect");
            send_stop_msg(stream);
            info!("Terminating Verification: the time bound was not satisfied by the prover");
            let terminate_vector = vec![1]; //Unfair(Time Reason)
            match sender.send(NotifyNode {
                buff: terminate_vector,
                notification: Notification::Terminate,
            }) {
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        "{:?} sent through the channel didn't reach the receiver\nReason: {}",
                        Notification::Terminate,
                        e.to_string()
                    )
                }
            };
        }
        Time_Verification_Status::Insufficient_Proofs => {
            warn!("--> Time_Verification_Status::Insufficient_Proofs");
    /*Do nothing*/ }
    }
}

fn handle_inclusion_proof(msg: &[u8], sender: &Sender<NotifyNode>) {
    //SO THE MESSAGE WILL BE EVENTALLY: TAG,HASH,block_id,byte_position,byte_value,proof
    let proof = from_bytes_to_proof(msg.to_vec());

    let mut root_hash_bytes: [u8; HASH_BYTES_LEN] = Default::default();
    root_hash_bytes.copy_from_slice(&msg[1..1 + HASH_BYTES_LEN]);

    let mut block_id_in_bytes: [u8; NUM_BYTES_PER_BLOCK_ID] = [0; NUM_BYTES_PER_BLOCK_ID];
    block_id_in_bytes
        .copy_from_slice(&msg[1 + HASH_BYTES_LEN..1 + HASH_BYTES_LEN + NUM_BYTES_PER_BLOCK_ID]);
    let block_id = u32::from_le_bytes(block_id_in_bytes);

    let mut position_in_byte: [u8; NUM_BYTES_PER_POSITION] = [0; NUM_BYTES_PER_POSITION];
    position_in_byte.copy_from_slice(
        &msg[1 + 32 + NUM_BYTES_PER_BLOCK_ID
            ..1 + 32 + NUM_BYTES_PER_BLOCK_ID + NUM_BYTES_PER_POSITION],
    );
    let position = u32::from_le_bytes(position_in_byte);

    let byte_value: u8 = msg[1 + 32 + NUM_BYTES_PER_BLOCK_ID + NUM_BYTES_PER_POSITION];

    let root_hash_computed = get_root_hash::<u8, (u32, u32)>(
        proof,
        byte_value,
        Id::<(u32, u32)>::new((block_id, position)),
    );
    let mut correctness_flag = 1; //Default: false
    if root_hash_computed.to_bytes() == root_hash_bytes {
        //convert to byte array the hash_retrieved. Then compare.
        correctness_flag = 0;
    }
    let mut update_new_proofs = Vec::new();
    update_new_proofs.push(1);
    update_new_proofs.push(correctness_flag);

    //HOE TO CHECK THAT ALL INCLUSION PROOFS WERE RECEIVED
    sender
        .send(NotifyNode {
            buff: update_new_proofs,
            notification: Notification::Update,
        })
        .unwrap();
}

fn verify_time_challenge_bound(counter: u8) -> Time_Verification_Status {
    if counter == 3 {
        //error!("counter == {}", counter);
        return Time_Verification_Status::Correct;
    }
    //error!("counter == {}", counter);
    return Time_Verification_Status::Insufficient_Proofs;
}

fn handle_stream<'a>(stream: &mut TcpStream, data: &'a mut [u8]) -> &'a [u8] {
    match stream.read(data) {
        Ok(size) => {
            trace!("reading data in handle_stream in verifier");
            return &data[..size];
        }
        Err(_) => {
            error!(
                "An error occurred, terminating connection with {}",
                stream.peer_addr().unwrap()
            );
            stream.shutdown(Shutdown::Both).unwrap();
            return &[];
        }
    }
}

fn handle_message(msg: &[u8], sender: Sender<NotifyNode>) {
    let tag = msg[0];
    //error!("Tag in verifier is == {}", msg[0]);
    if tag == 1 {
        debug!("Handle Verification of the proof");
        match sender.send(NotifyNode {
            buff: msg[1..].to_vec(),
            notification: Notification::Verification_Time,
        }) {
            Ok(_) => {
                debug!("good send to main")
            }
            Err(e) => {
                debug!("error first send channel == {}", e)
            }
        };
    } else if tag == 4 {
        info!("Handle Verification of the Inclusion Proof");
        match sender.send(NotifyNode {
            buff: msg[1..].to_vec(),
            notification: Notification::Handle_Inclusion_Proof,
        }) {
            Ok(_) => {
                debug!("good send to main")
            }
            Err(e) => {
                debug!("error first send channel == {}", e)
            }
        };
    } else {
        error!("In verifier the tag is NOT 1: the tag is {}", tag)
    }
}

fn attempt_connection() -> Option<String> {
    // Replace this with your actual connection logic
    // For the sake of example, let's say the connection succeeds after 3 attempts
    static mut ATTEMPT_COUNT: u32 = 0;

    unsafe {
        ATTEMPT_COUNT += 1;

        if ATTEMPT_COUNT <= 3 {
            None // Simulating a failed connection attempt
        } else {
            Some("Connected!".to_string()) // Simulating a successful connection attempt
        }
    }
}