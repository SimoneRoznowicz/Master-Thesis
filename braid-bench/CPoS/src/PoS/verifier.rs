use std::{str::Bytes, net::{TcpStream, Shutdown, TcpListener}, collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, sync::mpsc::{self, Sender, Receiver}, io::Read, thread};
use log::{info,error, warn, debug, trace};
use rand::{Rng, seq::SliceRandom};

use crate::{communication::{client::{send_msg},structs::{Phase, Notification}, handle_prover::random_path_generator}, block_generation::utils::Utils::{INITIAL_POSITION, INITIAL_BLOCK_ID, BATCH_SIZE, NUM_BLOCK_PER_UNIT, NUM_FRAGMENTS_PER_UNIT, NUM_PROOFS_TO_VERIFY, MAX_NUM_PROOFS}};

use super::structs::NotifyNode;

#[derive(Debug)]
pub struct Verifier {
    address: String,
    prover_address: String,
    seed: u8,
    stream: TcpStream
}

impl Verifier {

    pub fn start(address: String, prover_address: String){
        //channel to allow the verifier threads communicate with the main thread
        let sender: Sender<NotifyNode>;
        let receiver: Receiver<NotifyNode>;
        (sender,receiver) = mpsc::channel();

        let mut verifier = Verifier::new(address, prover_address, sender);

        //OVVIAMENTE QUA E IL PROBLEMA: MAIN HANDLER E' INFINITO. NON TONI A QUEL THREAD... FORSE METTI MAIN HANDLER SOTTO A UN NUOVO THREADS
        //INOLTRE DOVE USI GIA I THREADS, CONTROLLA CHE CREI PIU COPIE MA IN TEORIA SI DATO CHE CICLI
        info!("Verifier starting main_handler()");
        verifier.main_handler(&receiver);
        //verifier.challenge();
    }

    fn new(address: String, prover_address: String, sender: Sender<NotifyNode>) -> Verifier {
        let seed: u8 = rand::thread_rng().gen();
        //return Verifier {address, prover_address, seed}
        //let mut stream: Option<TcpStream> = None;
        let stream_option = TcpStream::connect(prover_address.clone());
        match &stream_option {
            Ok(stream) => {info!("Connection from verifier at {} and Prover at {} successfully created 
            ||\nConnection from verifier at {} and Prover at {} successfully created ",address, prover_address,&stream.local_addr().unwrap(),&stream.peer_addr().unwrap())},
            Err(_) => {error!("Error in connection")},
        };
        let stream = stream_option.unwrap();
        let mut this = Self {
            address,
            prover_address,
            seed,
            stream
        };
        this.start_server(sender);
        this
    }

    fn start_server(&mut self, sender: Sender<NotifyNode>) {
        let mut stream_clone = self.stream.try_clone().unwrap();
        thread::spawn(move || {
            loop{
                let sender_clone = sender.clone();
                //info!("New connection verification sss: {}", stream.peer_addr().unwrap());
                let mut data = [0; 128]; // Use a smaller buffer size
                handle_message(handle_stream(&mut stream_clone, &mut data), sender_clone);
            }
        });
        // info!("Verifier server listening on address sss {}", self.address);
        // let listener = TcpListener::bind(&self.stream.local_addr().unwrap()).unwrap();
        // thread::spawn(move || {
        //     trace!("Started loop in Verifier sss");
        //     for stream_option in listener.incoming() { //PALESEMENTE QUA SI BLOCCA!!!!
        //         trace!("IN VERIFIER NEW STREAM1!! sss");
        //             match stream_option {
        //                 Ok(mut stream) => {
        //                     loop{
        //                         let sender_clone = sender.clone();
        //                         info!("New connection verification sss: {}", stream.peer_addr().unwrap());
        //                         let mut data = [0; 128]; // Use a smaller buffer size
        //                         handle_message(handle_stream(&mut stream, &mut data), sender_clone);
        //                     }
        //                 }
        //                 Err(e) => {
        //                     error!("Error: {}", e)
        //                 }
        //             }
        //     }
        // });
    }

    fn main_handler(&mut self, receiver: &Receiver<NotifyNode>){
        let mut is_to_verify = true;
        let mut ii=0;
        while ii < 2 {
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
                    thread::spawn(move || {
                        match notification {
                            Notification::Verification => {
                                info!("Verifiier received notification: Verification");
                                //send challenge to prover for the execution
                                handle_verification(&stream_clone, &notify_node.buff);
                                //send_msg(&stream_clone, &notifyNode.buff);
                                info!("Notify the prover to stop sending proofs");
                            },
                            Notification::Continue => todo!(),
                            Notification::Stop => todo!(),
                        }
                    });
                },
                Err(e) => {warn!("Error == {}", e)},
            }
            is_to_verify = false;
            ii+=1;
        }
    }
    
    //the verifier sends a challenge composed of a seed σ, a proof of space id π, and a given byte position β.
    pub fn challenge(&mut self) {
        //tag is array[0].           tag == 0 -> CHALLENGE    tag == 1 -> VERIFICATION    tag == 2 -> STOP (sending proofs)
        let tag: u8 = 0; 
        let seed: u8 = rand::thread_rng().gen_range(0..=255);
        let msg: [u8; 2] = [tag,seed];
        //send challenge to prover for the execution
        send_msg(&mut self.stream, &msg);
        info!("Challenge sent to the verifier...");

        //self.start_client(&self.prover_address.clone(), &msg);
    }
    

    // fn start_client(&mut self, address: &String, msg: &[u8]) {
    //     let stream = TcpStream::connect(address);
    //     match stream {
    //         Ok(mut stream) => {
    //             info!("Successfully connected to address: {}", address);
    //             send_msg(&mut stream, msg);
    //         },
    //         Err(e) => {
    //             error!("Failed to connect: {}", e);
    //         }
    //     }
    //     info!("client terminated.");
    // } 
}

fn handle_verification(stream: &TcpStream, msg: &[u8]) -> bool {
    if(msg.len()>4){        //FAKE: TODO CONSIDERING THE BUFFER ALREADY STORED BY THE VERIFIER
        let msg_to_send: [u8; 1] = [2];
        send_msg(stream, msg)
    }
    return verify_time_challenge_bound() && verify_proofs(msg); //if the first is wrong, don't execute verify_proofs
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
    debug!("Before tag evaluation in the verifier");
    if tag == 1 {
        debug!("Thread in verifier notified of the new buffer. Send for verification to the main thread");
        // let ff = NotifyNode::new(msg, Notification::Verification);
        let not = Notification::Verification;
        let vec = msg.to_vec();
        let ff = NotifyNode{ buff: vec.clone(), notification: Notification::Verification };
        match sender.send(ff.clone()) {
            Ok(_) => {debug!("good")},
            Err(e) => {debug!("error first send channel == {}",e)},
        };
        // let ff2 = NotifyNode{ buff: vec, notification: Notification::Verification };

        // match sender.send(ff2){
        //     Ok(_) => {debug!("good")},
        //     Err(e) => {debug!("error first send channel == {}",e)},
        // };
    }

    // else if (tag == 2){
    //     //self.stop_sending_proofs(sender);            
    // }
    else{
        error!("Received wrong tag: this is a Prover, the round_id is {}", tag)
    }
}


