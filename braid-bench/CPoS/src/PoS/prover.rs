use std::io::Read;
use std::net::{TcpListener, Shutdown, TcpStream};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc::{Sender, self};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::channel;
use std::thread;

use aes::Block;
use log::{info, error};

use crate::block_generation::utils::Utils::{MAX_NUM_PROOFS, BATCH_SIZE, INITIAL_BLOCK_ID, INITIAL_POSITION};
use crate::communication::handle_prover::random_path_generator;
use crate::communication::structs::Signal;
use crate::communication::{client::start_client, structs::Phase};
use crate::block_generation::blockgen;

use super::structs::Node;
use super::verifier;

#[derive(Debug,Clone)]
pub struct Prover {
    address: String,
    verifier_address: String,
    //list_pos: Vec<Block>
}

impl Prover {
    pub fn new(address: String, verifier_address: String/*, list_pos: Vec<Block>*/) -> Prover {
        let this = Self {
            address,
            verifier_address,
        };
        
        let builder = thread::Builder::new().name("JOB_EXECUTOR".into());

        builder.spawn({
            let this = this.clone();
            move || this.listen()
        });

        this
    }

    pub fn start_server_verifier(&self){

    }
    // start_server(false, address.clone());
    pub fn init(&self) {
        //generate block group here        
    }
    
    pub fn execute(){

    }

    pub fn start_server(&self) {
        info!("Server listening on address {}", self.address);
        // accept connections and process them, spawning a new thread for each one
        self.spawn_listener_thread()
    }

    fn spawn_listener_thread(& self) {
        // let arc_self = Arc::new(RwLock::new(self));

        // let arc_clone = Arc::clone(&arc_self);
        // thread::spawn(move || {
        //     let locked_self = arc_clone.read().unwrap();
        //     locked_self.listen();
        // });



        // let x = Arc::new(Mutex::new(self.clone()));
        // let alias = x.clone();
        // { // launch thread asynchronuously...
        //      // will refer to the same Mutex<Foo>
        //     thread::spawn(|| {
        //         let mutref = alias.lock().unwrap(); 

        //         mutref.listen();
        //     });
        // }
    }

    pub fn listen(&self) {
        let listener = TcpListener::bind(&self.address).unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    info!("New connection: {}", stream.peer_addr().unwrap());
                    let mut data = [0 as u8; 200]; // MODIFIY TO USE THE MINIMUM LENGTH BUFFER
                    let mut slice = data.as_mut_slice();
                    let dataa = self.handle_stream(&mut stream, slice);
                    self.handle_message(dataa);
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
        let sender: Sender<Signal>;
        let receiver: Receiver<Signal>;
        (sender,receiver) = mpsc::channel();
        if(tag == 0){
            self.handle_challenge(msg, receiver);
        }
        else if (tag == 2){
            self.stop_sending_proofs(sender);            
        }
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
        
        start_client(&self.verifier_address, &response_msg);
        info!("Batch of proofs sent to the verifier");
    }

    pub fn stop_sending_proofs(&self, sender: mpsc::Sender<Signal>) {
        sender.send(Signal::Stop).unwrap();
    }
}
