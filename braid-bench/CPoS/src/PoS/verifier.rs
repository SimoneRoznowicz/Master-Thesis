use std::{str::Bytes, net::{TcpStream, Shutdown, TcpListener}, collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, sync::mpsc::{self, Sender, Receiver}, io::Read, thread, vec};
use log::{info,error, warn, debug, trace};
use rand::{Rng, seq::SliceRandom};

use crate::{communication::{client::{send_msg},structs::{Phase, Notification}, handle_prover::random_path_generator}, block_generation::utils::Utils::{INITIAL_POSITION, INITIAL_BLOCK_ID, BATCH_SIZE, NUM_BLOCK_PER_UNIT, NUM_FRAGMENTS_PER_UNIT, NUM_PROOFS_TO_VERIFY, MAX_NUM_PROOFS}};

use super::structs::NotifyNode;

#[derive(Debug)]
pub struct Verifier {
    address: String,
    prover_address: String,
    seed: u8,
    stream: TcpStream,
    stopped: bool,
    //proofs: Vec<u8>,
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
        let mut stopped = false;
        let mut this = Self {
            address,
            prover_address,
            seed,
            stream,
            stopped
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
                    info!("Receiver working");
                    let notification = notify_node.notification;
                    let stream_clone = self.stream.try_clone().unwrap();
                    let sender_clone = sender.clone();
                        match notification {
                            Notification::Verification => {
                                thread::spawn(move || {
                                    if is_stopped == false{
                                        info!("Verifiier received notification: Verification");
                                        if (handle_verification(&stream_clone, &notify_node.buff)){
                                            sender_clone.send(NotifyNode {buff: Vec::new(), notification: Notification::Stop}).unwrap();
                                        }
                                    }
                                    else{
                                        info!("Received notification Verification but this is not required at this point");
                                    }
                                });
                            },
                            Notification::Update => {
                                self.proof
                            }
                            Notification::Start => todo!(),
                            Notification::Stop => {
                                break;
                            },
                        }
                },
                Err(e) => {warn!("Error == {}", e)},
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

fn handle_verification(stream: &TcpStream, msg: &[u8],) -> bool {
    if(true){        
        let mut msg_to_send: [u8; 1] = [2];
        debug!("Sending Stop message to the prover: size msg_to_send[] == {}", msg_to_send[..][0]);
        send_msg(stream, &msg_to_send[..]);
        debug!("Stop message sent to the prover");
        return true;  //true because sent stop message
    }
    return false;        //verify_time_challenge_bound() && verify_proofs(msg); //if the first is wrong, don't execute verify_proofs
}


fn verify_time_challenge_bound() -> bool {
    return true;
}

fn verify_proofs(msg: &[u8]) -> bool {
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

fn sample_generate_verify(msg: &[u8], i: u32) -> bool {
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

fn handle_message(msg: &[u8], sender: Sender<NotifyNode>) {
    let tag = msg[0];
    debug!("Tag in verifier is == {}", msg[0]);
    if tag == 1 {
        debug!("Thread in verifier notified of the new buffer. Send for verification to the main thread");
        // let ff = NotifyNode::new(msg, Notification::Verification);
        let not = Notification::Verification;
        let vec = msg.to_vec();
        match sender.send(NotifyNode{ buff: vec.clone(), notification: Notification::Verification }) {
            Ok(_) => {debug!("good send to main")},
            Err(e) => {debug!("error first send channel == {}",e)},
        };
    }
    else{
        error!("In verifier the tag is NOT 1: the tag is {}", tag)
    }
}


