use aes::cipher::typenum::Len;
use log::{debug, error, info, trace, warn};
use rand::Rng;

use std::{
    collections::HashMap,
    io::Read,
    net::{Shutdown, TcpStream},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread::{self},
    time::Duration,
    vec,
};

use crate::{
    block_generation::{
        blockgen::GROUP_SIZE,
        utils::Utils::{
            FRAGMENT_SIZE, HASH_BYTES_LEN, INITIAL_BLOCK_ID, INITIAL_POSITION,
            NUM_BYTES_PER_BLOCK_ID, NUM_BYTES_PER_POSITION, VERIFIABLE_RATIO, BUFFER_DATA_SIZE,
        }, encoder::{generate_PoS, generate_xored_data},
    },
    communication::{
        client::send_msg,
        handle_prover::random_path_generator,
        structs::{
            Failure_Reason, Fairness, Notification, Time_Verification_Status, Verification_Status, NotifyNode,
        },
    },
    Merkle_Tree::client_verify::get_root_hash,
};

use super::utils::from_bytes_to_proof;

pub struct Verifier {
    prover_address: String,
    seed: u8,
    stream: TcpStream,
    proofs: Vec<u8>,
    is_fair: bool,
    is_terminated: bool,
    shared_mapping_bytes: Arc<Mutex<HashMap<(u32, u32), u8>>>, // k: (block_id,position) v: (byte_value)
    shared_blocks_hashes: Arc<Mutex<HashMap<u32, [u8;HASH_BYTES_LEN]>>>,
    //hash_root: [u8; HASH_LENGTH],
    status: (Verification_Status, Fairness),
    counter: u8,
}

impl Verifier {
    pub fn start(prover_address: String) {
        //channel to allow the verifier threads communicate with the main thread
        let sender: Sender<NotifyNode>;
        let receiver: Receiver<NotifyNode>;
        (sender, receiver) = mpsc::channel();

        let seed = rand::thread_rng().gen();
        debug!("SEED INITIALLY == {}", seed);

        let mut verifier = Verifier::new(prover_address, sender.clone(), seed);

        info!("Verifier starting main_handler()");
        verifier.main_handler(&receiver, &sender);
    }

    fn new(
        prover_address: String,
        sender: Sender<NotifyNode>,
        seed: u8,
    ) -> Verifier {
        let mut stream_option: Result<TcpStream, std::io::Error>;
        debug!("V: Arrived beginning new");
        loop {
            stream_option = TcpStream::connect(prover_address.clone());
            match stream_option {
                Ok(_) => {
                    info!("Connection Successful!");
                    break;
                }
                Err(_e) => {
                    warn!("Connection was not possible. Retry in 2 seconds...");
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }

        let stream = stream_option.unwrap();
        let proofs: Vec<u8> = Vec::new();
        let status = (Verification_Status::Executing, Fairness::Undecided);
        let is_fair = true;
        let is_terminated = false;
        let mapping_bytes: HashMap<(u32, u32), u8> = HashMap::new();
        let shared_mapping_bytes = Arc::new(Mutex::new(mapping_bytes));

        let blocks_hashes: HashMap<u32, [u8;HASH_BYTES_LEN]> = HashMap::new();
        let shared_blocks_hashes: Arc<Mutex<HashMap<u32, [u8; 32]>>> = Arc::new(Mutex::new(blocks_hashes));

        //let hash:[u8; HASH_LENGTH] = Default::default();
        let counter = 0;
        let mut this = Self {
            prover_address,
            seed,
            stream,
            proofs,
            is_fair,
            is_terminated,
            shared_mapping_bytes,
            shared_blocks_hashes,
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
                let mut data = [0; BUFFER_DATA_SIZE]; // Use a smaller buffer size
                handle_message(handle_stream(&mut stream_clone, &mut data), sender_clone);
            }
        });
    }

    fn main_handler(&mut self, receiver: &Receiver<NotifyNode>, sender: &Sender<NotifyNode>) {
        let mut is_commitment_needed = true;
        let mut is_ready = false;
        let mut is_to_challenge = true;
        let mut is_to_verify = true;
        let is_stopped = false;
        loop {
            if is_commitment_needed{
                is_commitment_needed = false;
                info!("Verifier asks the prover for commitment");
                self.request_commitment();
            }
            if is_to_challenge && is_ready {  //is_ready becomes true when I receive the hashes of the blocks
                is_to_challenge = false;
                info!("Verifier prepares the challenge");
                self.challenge();
            }
            match receiver.recv() {
                Ok(mut notify_node) => {
                    match notify_node.notification {
                        Notification::Handle_Prover_commitment => {
                            self.handle_prover_commitment(&notify_node.buff);
                            is_ready = true;
                        }
                        Notification::Verification_Time => {
                            if is_to_verify {
                                let stream_clone = self.stream.try_clone().unwrap();
                                let sender_clone = sender.clone();
                                let mut proofs_clone = self.proofs.clone();
                                self.counter += 1;
                                let counter_clone = self.counter;
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
                            self.verify_correctness_proofs(&notify_node.buff);
                        }

                        Notification::Handle_Inclusion_Proof => {
                            info!("Handle_Inclusion_Proof started");
                            let sender_clone = sender.clone();
                            let shared_map = Arc::clone(&self.shared_mapping_bytes);
                            let shared_blocks_hashes: Arc<Mutex<HashMap<u32, [u8; 32]>>> = Arc::clone(&self.shared_blocks_hashes);

                            thread::spawn(move || {
                                handle_inclusion_proof(
                                    &notify_node.buff,
                                    &sender_clone,
                                    shared_map,
                                    shared_blocks_hashes,
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
                                        sender
                                            .send(NotifyNode {
                                                buff: terminate_vector,
                                                notification: Notification::Terminate,
                                            })
                                            .unwrap();
                                    } else {
                                        info!("Correctly verified one proof ✅");
                                        if self.shared_mapping_bytes.lock().unwrap().is_empty() {
                                            self.is_terminated = true;
                                            self.is_fair = true;
                                            let terminate_vector = vec![0]; //Fair
                                            sender
                                                .send(NotifyNode {
                                                    buff: terminate_vector,
                                                    notification: Notification::Terminate,
                                                })
                                                .unwrap();
                                        } else {
                                            info!("Not all the requested proofs were received and verified");
                                            {
                                                let curr_map =
                                                    self.shared_mapping_bytes.lock().unwrap();
                                                info!(
                                                    "missing len == {}, missing map == {:?}",
                                                    curr_map.len(),
                                                    curr_map
                                                );
                                            }
                                        }
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
                                is_fair = Fairness::Unfair(Failure_Reason::Timeout)
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

    pub fn challenge(&mut self) {
        //tag is msg[0].           tag == 0 -> CHALLENGE    tag == 1 -> VERIFICATION    tag == 2 -> STOP (sending proofs)
        let tag: u8 = 0;
        let msg: [u8; 2] = [tag, self.seed];
        //send challenge to prover for the execution
        send_msg(&mut self.stream, &msg);
        info!("Challenge sent to the prover...");
    }

    pub fn handle_prover_commitment(&mut self, msg: &[u8]) {
        let mut curr = 0;
        let mut i = 0;
        while curr < msg.len() as usize {
            self.shared_blocks_hashes.lock().unwrap().insert(i, msg[curr..curr+HASH_BYTES_LEN].try_into().unwrap());

            curr += HASH_BYTES_LEN;
            i+=1;
        } 
    }

    pub fn request_commitment(&mut self) {
        let tag: u8 = 7;
        let msg: [u8; 1] = [tag];
        //send challenge to prover for the execution
        send_msg(&mut self.stream, &msg);
        info!("Request commitment to the prover...");
    }

    //V: Iteration: 0, block_id = 3, position = 195687, value = 192
    //P: Iteration: 0, block_id = 3, position = 195687, value = 192
    //Verify some of the proofs: generate the seed correspondent to all the proofs.
    //[0,*1,2,*3,4,5,*6,*7,8,*9]
    //[1,2,3,4,5]
    //update eg.  i = i + (1/3)*10
    //update i = i + (% of samples I want to test) * (length of proof vector)
    fn verify_correctness_proofs(&mut self, msg: &[u8]) -> bool {
        info!("Starting verify_correctness_proofs");
        let mut block_id: u32 = INITIAL_BLOCK_ID;
        let mut position: u32 = INITIAL_POSITION;
        let mut block_ids_pos: Vec<(u32, u32)> = vec![];

        for iteration in 0..msg.len() {
            (block_id, position, self.seed) = random_path_generator(self.seed, iteration as u8);
            block_ids_pos.push((block_id, position));
        }

        // let _proofs_len = msg.len() as u32;
        let mut verfiable_ratio = VERIFIABLE_RATIO;
        if VERIFIABLE_RATIO == 0.0 {
            warn!("VERIFIABLE_RATIO was set to 0: it was reset to 0.5");
            verfiable_ratio = 0.5;
        }
        let avg_step = (1.0 / verfiable_ratio).floor() as i32;
        let mut i: i32 = -avg_step;
        let mut random_step = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
        debug!("Average Step == {} + random Step == {}", avg_step, random_step);

        let mut verified_blocks_and_positions: Vec<u8> = vec![3];       //tag == 3 --> Send request to have a Merkle Tree proof for a specific u8 proof
        i = (i + ((avg_step + random_step) as i32)).abs();
        random_step = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);

        info!(
            "i == {}, Average Step == {} + random Step == {}",
            i, avg_step, random_step
        );

        let mut k = 0;
        while i < msg.len() as i32 {
            {
                self.shared_mapping_bytes.lock().unwrap().insert(
                    (block_ids_pos[i as usize].0, block_ids_pos[i as usize].1),
                    0,
                );
            }
            // debug!(
            //     "*I am printing blockid == {} and position == {}",
            //     block_id, position
            // );
            // warn!(
            //     "V: Iteration: {}, block_id = {}, position = {}, value = {}",
            //     i, block_ids_pos[i as usize].0, block_ids_pos[i as usize].1, msg[i as usize]
            // );
            // warn!("Indexxx == {}, msg before check == {:?}", i, msg);


            //IMPORTANTE RIMOSSO: in realta' fare questa verifica dopo, nell'inclusion proof verification. 
            //Qui i byte che salvi sono XORed. Quindi poi nell' incl proof, ricevi anche il data byte. 
            //A questo punto: 
            //   • per ogni XORed byte: crea il blocco CPoS corrispondente, seleziona il byte
            //   • Fai XOR di data byte (dato dal prover) con byte di CPoS e verifica che ottieni esattamente il 

            if !self.check_byte_value(
                block_ids_pos[i as usize].0,
                block_ids_pos[i as usize].1,
                msg[i as usize],
            ) {
                warn!("Found incorrect byte value while checking");
                return false;
            }



            //send request Merkle Tree for each of the proof: send tag 3 followed by the indexes (block_ids), followed by the positions
            //e.g. 3,block_id1,position1,blockid2,position2,block_id3,position3...
            debug!(
                "V: iteration=={} and block_id == {} and pos == {}",
                k, block_ids_pos[i as usize].0, block_ids_pos[i as usize].1
            );
            let block_id = block_ids_pos[i as usize].0.to_le_bytes();
            let position = block_ids_pos[i as usize].1.to_le_bytes();
            verified_blocks_and_positions.extend(block_id);
            verified_blocks_and_positions.extend(position);
            i = i + ((avg_step + random_step) as i32);
            // info!("Average Step == {} + random Step == {}", avg_step, random_step);
            random_step = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
            k += 1;
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
        // let block_group: Vec<[u64; GROUP_SIZE]> =
        //     generate_block_group((block_id / GROUP_SIZE as u32).try_into().unwrap());

        // let selected_arr: [u64; GROUP_SIZE] = block_group[(pos_in_block / 8) as usize]; //4 cells made of 8 bytes each

        // let mut array_u8: [u8; 8 * GROUP_SIZE] = [0; 8 * GROUP_SIZE];

        // for (i, &element) in selected_arr.iter().enumerate() {
        //     let bytes = element.to_le_bytes();
        //     array_u8[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        // }

        // let byte_value =
        //     array_u8[(block_id % GROUP_SIZE as u32) as usize * 8 + (pos_in_block % 8) as usize];

        // warn!(
        //     "byte_value_real == {} and byte_received == {}",
        //     byte_value, byte_received
        // );
        // debug!(
        //     "I am printing blockid == {} and position == {}",
        //     block_id, pos_in_block
        // );
        // {
        //     self.shared_mapping_bytes
        //         .lock()
        //         .unwrap()
        //         .insert((block_id, pos_in_block), byte_value);
        // }
        // return byte_value == byte_received;
        // 


        {
            self.shared_mapping_bytes
                .lock()
                .unwrap()
                .insert((block_id, pos_in_block), byte_received);
            debug!("byte_received ==== {}",byte_received);
        }

        return true;
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
    counter: u8, 
) {
    //note that new_proofs e proofs hanno gia rimosso il primo byte del tag
    //Update vector of proofs
    proofs.extend(new_proofs);

    send_update_notification(new_proofs, sender);

    match verify_time_challenge_bound(counter) {
        Time_Verification_Status::Correct => {
            info!("--> Time_Verification_Status::Correct");
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
            /*Do nothing*/
        }
    }
}

fn handle_inclusion_proof(
    msg: &[u8],
    sender: &Sender<NotifyNode>,
    shared_map: Arc<Mutex<HashMap<(u32, u32), u8>>>,
    shared_blocks_hashes: Arc<Mutex<HashMap<u32, [u8; 32]>>>,
) {
    let mut curr_indx = 0;
    //SO THE MESSAGE WILL BE EVENTALLY: HASH,block_id,byte_position,self_fragment,proof
    //debug!("V: Inside handle_inclusion_proof func msg == {:?}", msg);
    let mut root_hash_bytes: [u8; HASH_BYTES_LEN] = Default::default();
    root_hash_bytes.copy_from_slice(&msg[..HASH_BYTES_LEN]);
    curr_indx += HASH_BYTES_LEN;

    let mut block_id_in_bytes: [u8; NUM_BYTES_PER_BLOCK_ID] = [0; NUM_BYTES_PER_BLOCK_ID];
    block_id_in_bytes.copy_from_slice(&msg[curr_indx..curr_indx + NUM_BYTES_PER_BLOCK_ID]);
    let block_id = u32::from_le_bytes(block_id_in_bytes);
    curr_indx += NUM_BYTES_PER_BLOCK_ID;

    let mut position_in_bytes: [u8; NUM_BYTES_PER_POSITION] = [0; NUM_BYTES_PER_POSITION];
    position_in_bytes.copy_from_slice(&msg[curr_indx..curr_indx + NUM_BYTES_PER_POSITION]);
    let position = u32::from_le_bytes(position_in_bytes);
    curr_indx += NUM_BYTES_PER_POSITION;

    let mut self_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
    self_fragment.copy_from_slice(&msg[curr_indx..curr_indx + FRAGMENT_SIZE]);
    curr_indx += FRAGMENT_SIZE;

    let proof = from_bytes_to_proof(msg[curr_indx..].to_vec());
    //After retrieving the elements: insert the byte to be proved in the self_fragment at the correct index. Then, using something similar to the method get_root_hash retrieve the hash of the root

    debug!("V handle_inclusion_proof: len(root_hash_bytes) == {}, block_id == {}, position_in_byte == {}", root_hash_bytes.len(), block_id, position);

    // let mut buffer = vec![0; HASH_BYTES_LEN + NUM_BYTES_IN_BLOCK_GROUP as usize];
    // read_hash_and_block_from_output_file(&self.shared_file, block_ids[indx], &mut buffer);
    // let reconstructed_buffer = reconstruct_raw_data(0, &buffer);

    // let group: Vec<[u64; 4]> = generate_PoS(block_id as u64, shared_blocks_hashes.lock().unwrap()[&block_id]);

    let raw_byte = self_fragment[(position % FRAGMENT_SIZE as u32) as usize];
    let mut xored_byte: u8 = 0;
    {
        let map = shared_map.lock().unwrap();
        match map.get(&(block_id.clone(), position.clone()))
        {
            Some(value) => {
                //self_fragment[indx_byte_in_self_fragment as usize] = *value;
                xored_byte = *value;
                warn!("Check this inclusion proof with my innput value. block_id == {}, position {}, value {}, \nMap == {:?}", block_id, position, *value, map);
            }
            None => {
                error!("Do not check this inclusion proof with my innput value. block_id == {} and position {} Map == {:?}", block_id, position, map);
            }
        };
    }

    let computed_xored_fragment = generate_xored_data(block_id, position, shared_blocks_hashes.lock().unwrap()[&block_id], self_fragment, false);

    let computed_xored_byte = computed_xored_fragment[position as usize%FRAGMENT_SIZE as usize];
    debug!("V real xored_byte is {}\n while your computed xored byte is in {:?}\n while computed xored byte is {}", xored_byte, computed_xored_fragment, computed_xored_byte);


    let root_hash_computed =
        get_root_hash(&proof, (block_id, position), &shared_map, self_fragment);
    let mut correctness_flag = 1;


    let root_hash_computed_bytes = root_hash_computed.as_bytes();
    let block_hashes;
    {
        block_hashes = shared_blocks_hashes.lock().unwrap();
        debug!(
            "root_hash_computed.as_bytes() == {:?}\n root_hash_bytes == {:?}\nblock_hashes[&block_id] == {:?}",
            root_hash_computed.as_bytes(),root_hash_bytes,block_hashes[&block_id]
        );
    }
    if root_hash_computed_bytes == &root_hash_bytes && root_hash_computed_bytes == &block_hashes[&block_id] {
        //convert to byte array the hash_retrieved. Then compare.
        info!("Successful Inclusion proof");
        correctness_flag = 0;
        {
            debug!("map before == {:?}", shared_map.lock().unwrap());
        }
        {
            shared_map.lock().unwrap().remove(&(block_id, position));
        }
    }
    let mut update_new_proofs = Vec::new();
    update_new_proofs.push(1);
    update_new_proofs.push(correctness_flag);

    sender
        .send(NotifyNode {
            buff: update_new_proofs,
            notification: Notification::Update,
        })
        .unwrap();
}

fn verify_time_challenge_bound(counter: u8) -> Time_Verification_Status {
    if counter == 10 {
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
    if !msg.is_empty(){
        let tag = msg[0];
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
                Ok(_) => {}
                Err(e) => {
                    debug!("error first send channel == {}", e)
                }
            };
        } else if tag == 8 {
            info!("Handle prover's commitment");
            match sender.send(NotifyNode {
                buff: msg[1..].to_vec(),
                notification: Notification::Handle_Prover_commitment,
            }) {
                Ok(_) => {}
                Err(e) => {
                    debug!("error first send channel == {}", e)
                }
            };
        } else {
            error!("In verifier the tag is NOT 1: the tag is {}", tag)
        }
    }
}
