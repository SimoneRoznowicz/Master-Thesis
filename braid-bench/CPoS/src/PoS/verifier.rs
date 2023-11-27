use std::{str::Bytes, net::{TcpStream, Shutdown, TcpListener}, collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, sync::mpsc::{self, Sender, Receiver}, io::Read, thread, vec};
use log::{info,error, warn, debug, trace};
use rand::{Rng, seq::SliceRandom};

use crate::{communication::{client::{send_msg},structs::{Notification, Fairness, Verification_Status, Failure_Reason, Time_Verification_Status}, handle_prover::random_path_generator}, block_generation::utils::Utils::{INITIAL_POSITION, INITIAL_BLOCK_ID, BATCH_SIZE, NUM_BLOCK_PER_UNIT, NUM_FRAGMENTS_PER_UNIT, NUM_PROOFS_TO_VERIFY, MAX_NUM_PROOFS}};

use super::structs::NotifyNode;

pub struct Verifier {
    address: String,
    prover_address: String,
    seed: u8,
    stream: TcpStream,
    proofs: Vec<u8>,
    status: (Verification_Status,Fairness)  //
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
            Ok(stream) => {info!("Connection from verifier at {} and Prover at {} successfully created 
            ||\nConnection from verifier at {} and Prover at {} successfully created ",address, prover_address,&stream.local_addr().unwrap(),&stream.peer_addr().unwrap())},
            Err(_) => {error!("Error in connection")},
        };
        let stream = stream_option.unwrap();
        let mut proofs: Vec<u8> = Vec::new();
        let mut status = (Verification_Status::Executing,Fairness::Undecided);
        let mut this = Self {
            address,
            prover_address,
            seed,
            stream,
            proofs,
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
        let mut is_to_verify = true;
        let mut is_stopped = false;
        loop {
            if is_to_verify {
                info!("Verifier prepares the challenge");
                self.challenge();
            }
            info!("Before Recv");
            match receiver.recv() {
                Ok(notify_node) => {
                    match notify_node.notification {
                        Notification::Verification_Time => {
                            let stream_clone = self.stream.try_clone().unwrap();
                            let sender_clone = sender.clone();        
                            let mut proofs_clone = self.proofs.clone();
                            thread::spawn(move || {
                                if is_stopped == false {
                                    info!("Verifiier received notification: Verification");
                                    handle_verification(&stream_clone, &notify_node.buff, &mut proofs_clone, &sender_clone);
                                }
                                else{
                                    info!("Received notification Verification but this is not required at this point");
                                }
                            });
                        },
                        Notification::Verification_Correctness => {
                            let mut proofs_clone = self.proofs.clone();
                            thread::spawn(move || {
                                verify_proofs(&proofs_clone);
                            });
                        },
                        Notification::Update => {
                            self.proofs.extend(notify_node.buff);
                        },
                        Notification::Terminate => { 
                            let is_fair: Fairness;
                            //0-->Fair; 1-->Unfair(Time Reason); 2-->Unfair(Correctness Reason)
                            if (notify_node.buff[0] == 0) {is_fair = Fairness::Fair} 
                            else if (notify_node.buff[0] == 1) {is_fair = Fairness::Unfair(Failure_Reason::Time)}
                            else {is_fair = Fairness::Unfair(Failure_Reason::Correctness)}
                            self.status = (Verification_Status::Terminated, is_fair);
                            info!("***************************\nResult of the Challenge:{:?}\n***************************", self.status);
                            //if needed you can reset the status here
                            break;
                        }
                        _ => {error!("Unexpected Notification of type {:?}", notify_node.notification)}
                    }
                },
                Err(e) => {warn!("Error == {}", e)}
            }
            is_to_verify = false;
        }
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
}


fn handle_verification(stream: &TcpStream, new_proofs: &[u8], proofs: &mut Vec<u8>, sender: &Sender<NotifyNode>) {
    //Update vector of proofs
    proofs.extend(new_proofs);
    sender.send(NotifyNode {buff: new_proofs.to_vec(), notification: Notification::Update}).unwrap();
    //verify_time_challenge_bound() should return three cases: 
    //Still not verified
    //Verified Correct (we can proceed to verify the correctness of the proofs)
    //Verified Not Correct
    match verify_time_challenge_bound() {
        Time_Verification_Status::Correct => {
            info!("Sending Stop message to the prover");
            let msg_to_send: [u8; 1] = [2];
            send_msg(stream, &msg_to_send[..]);
    
            info!("Starting correctness verifications of the proofs");
            sender.send(NotifyNode {buff: proofs.to_vec(), notification: Notification::Verification_Correctness}).unwrap();    
        },
        Time_Verification_Status::Incorrect => {
            info!("Terminating Verification: the time bound was not satisfied by the prover");
            let my_vector = vec![1];  //Unfair(Time Reason)
            sender.send(NotifyNode {buff: my_vector, notification: Notification::Terminate}).unwrap();        
        },
        Time_Verification_Status::Insufficient_Proofs => {/*Do nothing*/}
    }
}

fn verify_time_challenge_bound() -> Time_Verification_Status{
    return Time_Verification_Status::Insufficient_Proofs;
}

///Verify some of the proofs: generate the seed correspondent to all the proofs. 
fn verify_proofs(msg: &[u8]) -> bool {
    let mut rng = rand::thread_rng();
    let mut shuffled_elements: Vec<u8> = msg.to_vec();
    shuffled_elements.shuffle(&mut rng);

    for i in 0..NUM_PROOFS_TO_VERIFY {
        if(!sample_generate_verify(msg,i)){
            return false;
        };
    }
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
        let vec = msg.to_vec();
        match sender.send(NotifyNode{ buff: vec.clone(), notification: Notification::Verification_Time }) {
            Ok(_) => {debug!("good send to main")},
            Err(e) => {debug!("error first send channel == {}",e)},
        };
    }
    else{
        error!("In verifier the tag is NOT 1: the tag is {}", tag)
    }
}


