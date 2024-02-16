use aes::cipher::typenum::Len;
use log::{debug, error, info, trace, warn};
use rand::{distributions::Bernoulli, Rng};

use std::{
    collections::HashMap,
    io::Read,
    net::{Shutdown, TcpStream},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread::{self},
    time::{Duration, Instant, SystemTime},
    vec,
};

use crate::{
    block_generation::{
        blockgen::GROUP_SIZE,
        encoder::{generate_PoS, generate_xored_data},
        utils::Utils::{
            BAD_PROOF_AVG_TIMING, BUFFER_DATA_SIZE, FRAGMENT_SIZE, GOOD_PROOF_AVG_TIMING,
            HASH_BYTES_LEN, INITIAL_BLOCK_ID, INITIAL_POSITION, LOWEST_ACCEPTED_STORING_PERCENTAGE,
            NUM_BYTES_PER_BLOCK_ID, NUM_BYTES_PER_POSITION, TIME_LIMIT, VERIFIABLE_RATIO,
        },
    },
    communication::{
        client::send_msg,
        path_generator::random_path_generator,
        structs::{
            Failure_Reason, Fairness, Notification, NotifyNode, Time_Verification_Status,
            Verification_Status,
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
    shared_blocks_hashes: Arc<Mutex<HashMap<u32, [u8; HASH_BYTES_LEN]>>>,
    status: (Verification_Status, Fairness),
    counter: u8,
    shared_start_time: Arc<Mutex<Instant>>,
}

impl Verifier {

    //Entry point to execute a Verifier instance
    pub fn start(prover_address: String) {
        //channel to allow the verifier threads communicate with the main thread
        let sender: Sender<NotifyNode>;
        let receiver: Receiver<NotifyNode>;
        (sender, receiver) = mpsc::channel();

        //initial seed for the incoming challenge
        let seed = rand::thread_rng().gen();
        debug!("seed initially == {}", seed);

        let mut verifier = Verifier::new(prover_address, sender.clone(), seed);

        info!("Verifier starting main_handler()");
        verifier.main_handler(&receiver, &sender);
    }

    fn new(prover_address: String, sender: Sender<NotifyNode>, seed: u8) -> Verifier {
        let mut stream_option: Result<TcpStream, std::io::Error>;
        //Try connecting to prover until successful
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

        let blocks_hashes: HashMap<u32, [u8; HASH_BYTES_LEN]> = HashMap::new();
        let shared_blocks_hashes: Arc<Mutex<HashMap<u32, [u8; HASH_BYTES_LEN]>>> =
            Arc::new(Mutex::new(blocks_hashes));
        let mut shared_start_time = Arc::new(Mutex::new(Instant::now()));
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
            shared_start_time,
        };
        this.start_server(sender);
        this
    }

    /*
     * Server implementation: the verifier keeps listening on the tcpstream endpoint. When a new message is detected,
     * it is handled separely in the handle_message function.
     */
    fn start_server(&mut self, sender: Sender<NotifyNode>) {
        let mut stream_clone = self.stream.try_clone().unwrap();
        thread::spawn(move || {
            loop {
                let sender_clone = sender.clone();
                let mut data = vec![0; BUFFER_DATA_SIZE]; // Use a smaller buffer size
                handle_message(handle_stream(&mut stream_clone, &mut data), sender_clone);
            }
        });
    }

    /*
     * This is the job scheduler of the verifier.
     */
    fn main_handler(&mut self, receiver: &Receiver<NotifyNode>, sender: &Sender<NotifyNode>) {
        let mut is_commitment_needed = true;
        let mut is_ready = false;
        let mut is_to_challenge = true;
        let mut is_to_verify = true;
        let is_stopped = false;
        loop {
            if is_commitment_needed {
                is_commitment_needed = false;
                info!("Verifier asks the prover for commitment");
                self.request_commitment();
            }
            if is_to_challenge && is_ready {
                is_to_challenge = false;
                info!("Verifier prepares the challenge");
                {
                    *self.shared_start_time.lock().unwrap() = Instant::now();
                }
                self.challenge();
            }
            match receiver.recv() {
                Ok(mut notify_node) => {
                    match notify_node.notification {
                        Notification::Handle_Prover_commitment => {
                            self.handle_commitment(&notify_node.buff);
                            is_ready = true;
                        }

                        Notification::Verification_Time => {
                            if is_to_verify {
                                let stream_clone = self.stream.try_clone().unwrap();
                                let sender_clone = sender.clone();
                                let mut proofs_clone = self.proofs.clone();
                                self.counter += 1;
                                let counter_clone = self.counter;
                                let shared_start_time: Arc<Mutex<Instant>> =
                                    Arc::clone(&self.shared_start_time);
                                let time_curr = Instant::now();
                                Some(thread::spawn(move || {
                                    if is_stopped == false {
                                        info!("Verifier received notification: Verification");
                                        let time_curr = Instant::now();
                                        handle_verification(
                                            &stream_clone,
                                            &notify_node.buff,
                                            &mut proofs_clone,
                                            &sender_clone,
                                            counter_clone,
                                            shared_start_time,
                                            time_curr,
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
                            let shared_blocks_hashes: Arc<Mutex<HashMap<u32, [u8; 32]>>> =
                                Arc::clone(&self.shared_blocks_hashes);

                            thread::spawn(move || {
                                handle_inclusion_proof(
                                    &notify_node.buff,
                                    &sender_clone,
                                    shared_map,
                                    shared_blocks_hashes,
                                );
                            });
                        }

                        //The Update notification can be used for multiple goals:
                        //one is updating the vector of proofs currently received by the prover
                        //one is to terminate the protocol execution when all the proofs are received or a wrong proof was detected
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
                                                debug!(
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
                                is_fair = Fairness::Successful
                            } else if notify_node.buff[0] == 1 {
                                is_fair = Fairness::Failure(Failure_Reason::Timeout)
                            } else {
                                is_fair = Fairness::Failure(Failure_Reason::Incorrect)
                            }
                            self.status = (Verification_Status::Terminated, is_fair);
                            let total_time = (Instant::now() - *self.shared_start_time.lock().unwrap()).as_millis();
                            error!("\n***************************\nResult of the Challenge:{:?}\ntotal time =={:?}\n***************************", self.status,total_time);
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
        //When the protocol is terminated sleep some seconds to let other threads terminate as well
        thread::sleep(Duration::from_secs(5));
    }

    /*
     * The verifier requests the prover to commit to some raw data for the whole duration of the protocol execution.
     */
    pub fn request_commitment(&mut self) {
        let tag: u8 = 7;
        let msg: [u8; 1] = [tag];
        //send challenge to prover for the execution
        send_msg(&mut self.stream, &msg);
        info!("Request commitment to the prover...");
    }

    /*
     * The verifier collects the hashes of the roots for each given block. This is the commitment made by the prover.
     */
    pub fn handle_commitment(&mut self, msg: &[u8]) {
        let mut curr = 0;
        let mut i = 0;
        while curr < msg.len() {
            {
                self.shared_blocks_hashes
                    .lock()
                    .unwrap()
                    .insert(i, msg[curr..curr + HASH_BYTES_LEN].try_into().unwrap());
            }
            curr += HASH_BYTES_LEN;
            i += 1;
        }
        debug!(
            "Verifier commitment blocks map == {:?}",
            self.shared_blocks_hashes.lock().unwrap()
        );
    }

    /*
     * The verifier starts the challenge by sending a message to the prover, containing the initial seed.
     */
    pub fn challenge(&mut self) {
        let tag: u8 = 0;
        let msg: [u8; 2] = [tag, self.seed];
        //send challenge to prover for the execution
        send_msg(&mut self.stream, &msg);
        info!("Challenge sent to the prover...");
    }

    /*
     * Start Correctness Verification: the random path generator is executed so that the verifier knows what proof to expect
     * and therefore check whether the prover cheated. Moreover, the verifier will require Inclusion Proofs for some of the received proofs
     */
    fn verify_correctness_proofs(&mut self, msg: &[u8]) -> bool {
        info!("Starting verify_correctness_proofs");
        let mut block_id: u32 = INITIAL_BLOCK_ID;
        let mut position: u32 = INITIAL_POSITION;
        let mut block_ids_pos: Vec<(u32, u32)> = vec![];

        for iteration in 0..msg.len() {
            (block_id, position, self.seed) = random_path_generator(self.seed, iteration as u64);
            block_ids_pos.push((block_id, position));
        }

        let mut verfiable_ratio = VERIFIABLE_RATIO;
        if VERIFIABLE_RATIO == 0.0 {
            warn!("VERIFIABLE_RATIO was set to 0: it was reset to 0.5");
            verfiable_ratio = 0.5;
        }
        let avg_step = (1.0 / verfiable_ratio).floor() as i32;
        let mut i: i32 = -avg_step;
        let mut random_step = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
        debug!(
            "Average Step == {} + random Step == {}",
            avg_step, random_step
        );

        let mut verified_blocks_and_positions: Vec<u8> = vec![3]; //tag == 3 --> Send request to have a Merkle Tree proof for a specific u8 proof
        i = (i + ((avg_step + random_step) as i32)).abs();
        random_step = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);

        debug!(
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
            {
                self.shared_mapping_bytes.lock().unwrap().insert(
                    (block_ids_pos[i as usize].0, block_ids_pos[i as usize].1),
                    msg[i as usize],
                );
                debug!("byte_received ==== {}", msg[i as usize]);
            }

            //send request Inclusion Proof for each of the selected proofs: send tag 3 followed by the indexes (block_ids), followed by the positions
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

        {
            let map = self.shared_mapping_bytes.lock().unwrap();
            debug!(
                "Map completely created len == {:?}\n map == {:?}",
                map.len(),
                map
            );
        }
        send_msg(&self.stream, &verified_blocks_and_positions);
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
    shared_time_start: Arc<Mutex<Instant>>,
    time_curr: Instant,
) {
    //note that new_proofs e proofs hanno gia rimosso il primo byte del tag
    //Update vector of proofs
    proofs.extend(new_proofs);

    send_update_notification(new_proofs, sender);

    match verify_time_challenge_bound(counter, proofs, shared_time_start, time_curr) {
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

/*
* Perform all the Correctness Verification steps for each received Inclusion Proof, as described in the thesis.
*/
fn handle_inclusion_proof(
    msg: &[u8],
    sender: &Sender<NotifyNode>,
    shared_map: Arc<Mutex<HashMap<(u32, u32), u8>>>,
    shared_blocks_hashes: Arc<Mutex<HashMap<u32, [u8; 32]>>>,
) {
    let mut curr_indx = 0;

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

    debug!("V handle_inclusion_proof: len(root_hash_bytes) == {}, block_id == {}, position_in_byte == {}", root_hash_bytes.len(), block_id, position);

    let computed_xored_fragment = generate_xored_data(
        block_id,
        position,
        shared_blocks_hashes.lock().unwrap()[&block_id],
        self_fragment,
        false,
    );

    let mut c_xored_byte = computed_xored_fragment[position as usize % FRAGMENT_SIZE as usize];

    let raw_byte = self_fragment[(position % FRAGMENT_SIZE as u32) as usize];
    let mut xored_byte: u8 = 0;
    {
        let map = shared_map.lock().unwrap();
        match map.get(&(block_id, position)) {
            Some(value) => {
                xored_byte = *value;
                debug!("Check this inclusion proof with my innput value. block_id == {}, position {}, value {}, map.len =={}\nMap == {:?}", block_id, position, *value, map.len(), map);
            }
            None => {
                // error!("Do not check this inclusion proof with my innput value. block_id == {} and position {}, map.len =={} Map == {:?}", block_id, position, map.len(), map);
                return;
            }
        };
    }


    let root_hash_computed =
        get_root_hash(&proof, (block_id, position), &shared_map, self_fragment);
    c_xored_byte = xored_byte;
    let mut correctness_flag = 1;

    let root_hash_computed_bytes = root_hash_computed.as_bytes();
    let block_hashes;
    {
        block_hashes = shared_blocks_hashes.lock().unwrap();
        debug!(
            "root_hash_computed.as_bytes() == {:?}\n root_hash_bytes == {:?}\n block_hashes[&block_id] == {:?}",
            root_hash_computed.as_bytes(),root_hash_bytes,block_hashes[&block_id]
        );
    }

    //Checking the three inclusion proof checks
    if root_hash_computed_bytes == &root_hash_bytes
        && root_hash_computed_bytes == &block_hashes[&block_id]
        && c_xored_byte == xored_byte
    {
        info!("Successful Inclusion proof");
        correctness_flag = 0;
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

/*
* Perform the time Verification check.
*/
fn verify_time_challenge_bound(
    counter: u8,
    proofs: &Vec<u8>,
    shared_time_start: Arc<Mutex<Instant>>,
    time_curr: Instant,
) -> Time_Verification_Status {
    //Here are the average time to generate a bad proof or collect a good proof

    let time_start;
    {
        time_start = shared_time_start.lock().unwrap().to_owned();
    }
    let delta_time = (time_curr - time_start).as_micros();
    debug!("proofs len == {}", proofs.len());
    debug!("delta time == {}", delta_time);

    let (good_proof_count, bad_proof_count) = estimate_number_g_and_b(
        proofs.len(),
        delta_time,
        GOOD_PROOF_AVG_TIMING,
        BAD_PROOF_AVG_TIMING,
    );
    let p = good_proof_count as f64 / (bad_proof_count + good_proof_count) as f64;
    let std = (1.0 / (proofs.len() as f64).sqrt()) * (p * (1.0 - p)).sqrt();
    let inf = -2.576 * std + p;
    let sup = 2.576 * std + p;
    info!("inf == {} and sup == {}", inf, sup);
    debug!("good_proof_count == {}", good_proof_count);
    debug!("bad_proof_count == {}", bad_proof_count);
    debug!("p == {}", p);

    //We assume theta being 0.08
    if sup - inf < 0.08 {
        if (sup + inf) / 2.0 >= LOWEST_ACCEPTED_STORING_PERCENTAGE as f64 {
            info!("Stop Verification time Successful");
            return Time_Verification_Status::Correct;
        }
    }

    if delta_time > TIME_LIMIT {
        error!("Stop Verification time FAILED");
        return Time_Verification_Status::Incorrect;
    }

    return Time_Verification_Status::Insufficient_Proofs;
}

/*
* Estimate the number of good and bad proofs knowing the amount of time passed.
*/
fn estimate_number_g_and_b(
    n: usize,
    target: u128,
    good_elem: u128,
    bad_elem: u128,
) -> (u128, u128) {
    let mut sum = 0;
    let mut iter = 0;
    let mut good_count = 0;
    let mut bad_count = 0;
    while iter < n {
        if sum < target {
            sum += bad_elem;
            bad_count += 1;
        } else {
            sum += good_elem;
            good_count += 1;
        }
        iter += 1;
    }
    //let's be more precise, maybe  overestimated the bad proofs number
    if sum >= target + bad_count {
        good_count += 1;
        bad_count -= 1;
        sum = sum + good_count - bad_count;
    }

    return (good_count, bad_count);
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

/*
* Generate a NotifyNode specific for each tag received. This NotifyNode will be received by the
* main_handler function that will take action according to the related message
*/
fn handle_message(msg: &[u8], sender: Sender<NotifyNode>) {
    if !msg.is_empty() {
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
