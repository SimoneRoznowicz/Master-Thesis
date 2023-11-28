use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, Shutdown, TcpStream};
use std::option;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc::{Sender, self, TryRecvError};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::channel;
use std::thread::{self, Thread};

use aes::Block;
use log::{info, error, debug, trace, warn};

use crate::block_generation::encoder::generate_block;
use crate::block_generation::utils::Utils::{MAX_NUM_PROOFS, BATCH_SIZE, INITIAL_BLOCK_ID, INITIAL_POSITION, NUM_BLOCK_PER_UNIT};
use crate::communication::client::{send_msg_prover, send_msg};
use crate::communication::handle_prover::random_path_generator;
use crate::communication::structs::Notification;
use crate::block_generation::blockgen::{self, BlockGroup};

use super::structs::NotifyNode;
use super::verifier;

#[derive(Debug)]
pub struct Prover {
    address: String,
    verifier_address: String,
    stream_opt: Option<TcpStream>,
    unit: Vec<BlockGroup>,   //maybe then you should substitute this BlockGroup with a File
    seed: u8
}

impl Prover {

    pub fn start(address: String, prover_address: String){
        //channel to allow the verifier threads communicate with the main thread
        let sender: Sender<NotifyNode>;
        let receiver: Receiver<NotifyNode>;
        (sender,receiver) = mpsc::channel();

        let mut verifier = Prover::new(address, prover_address, sender);

        info!("Prover starting main_handler()");
        verifier.main_handler(&receiver);
    }

    pub fn new(address: String, verifier_address: String, sender: Sender<NotifyNode>) -> Prover {
        debug!("beginning of new Prover");
        let mut unit: Vec<BlockGroup> = Vec::new();

        for i in 0..NUM_BLOCK_PER_UNIT {
            debug!("Before first block generate");
            unit.push(generate_block(i));
        }
        debug!("After block generation");
        let mut encoded: Vec<u8> = bincode::serialize(&unit).unwrap();
        let enc_slice: &[u8] = encoded.as_mut_slice();
        // Write the serialized data to a file
                    //let mut file = File::create("serailized_file.bin").unwrap();
        //file.write_all(&encoded)?;
                    //file.write_all(&enc_slice);
        let stream: Option<TcpStream> = None;
        let mut this = Self {
            address,
            verifier_address,
            stream_opt: stream,
            unit,
            seed: 0     //default value
        };

        this.start_server(sender);

        this
    }
    
    pub fn start_server(&mut self, sender: Sender<NotifyNode>) {
        info!("Prover server listening on address {}", self.address);
        let listener = TcpListener::bind(&self.address).unwrap();
        let mut stream = listener.accept().unwrap().0;
        self.stream_opt = Some(stream.try_clone().unwrap());
         
        //let read_stream = Arc::clone(&shared_stream);
        //let write_stream = Arc::clone(&shared_stream);

        //clone self strema
        //let mut stream_clone = Some(self.stream_opt.unwrap().try_clone().unwrap());//stream.try_clone().unwrap();

        thread::spawn(move || {
            loop{   //secondo me in qualche modo non rilascia qua
                //trace!("Started loop in prover");
                let sender_clone = sender.clone();
                let mut stream_clone = stream.try_clone().unwrap();
                //info!("New connection: {}", stream.peer_addr().unwrap());
                let mut data = [0; 128]; // Use a smaller buffer size
                let retrieved_data = handle_stream(&mut stream_clone, &mut data);
                handle_message(retrieved_data, sender_clone);
            }
        });
    }

    pub fn main_handler(&mut self, receiver: &Receiver<NotifyNode>) {
        let mut counter = 0;
        let mut is_started = false;
        // while counter < MAX_NUM_PROOFS {
        loop{
            match receiver.try_recv() {  //PROBLEMA: QUA SI FERMA SEMPRE. MI SERVIREBBE UNA NOTIFICA CONTINUE A OGNI CICLO. INVECE IO VORREI UNA NOTIFICA STOP QUANDO SERVE E NEL RESTO DEL TEMPO RIMANE CONTINUE
                Ok(notify_node) => {
                    match notify_node.notification {
                        Notification::Start => {
                            is_started = true;
                            info!("Start Notification received");
                            self.seed = notify_node.buff[1];
                            create_and_send_proof_batches(&self.stream_opt, self.seed, &receiver);
                        }
                        Notification::Stop => {
                            info!("Received Stop signal: the prover stopped sending proof batches");
                            break;
                        }
                        _ => {error!("unexpected notification received")}
                    }
                }
                Err(TryRecvError::Empty) => {
                    if(is_started){
                        create_and_send_proof_batches(&self.stream_opt, self.seed, &receiver);
                    }
                    warn!("In TryRecvError::Empty send batches");
                }
                Err(TryRecvError::Disconnected) => {
                    error!("The prover has been disconnected");
                    break;
                }
            }
            counter += BATCH_SIZE*10;
        }
        info!("ARRIVED AT END OF LOOP");
    }
}

pub fn stop_sending_proofs(sender: &Sender<NotifyNode>) {
    match sender.send(NotifyNode {buff: Vec::new(), notification: Notification::Stop}) {
        Ok(_) => {},
        Err(_) => {warn!("This stop Notification not received")},
    };
}

pub fn handle_stream<'a>(stream: &mut TcpStream, data: &'a mut [u8]) -> &'a[u8] {
    // let mut stream_opt_clone = stream_opt.clone();
    // let mut locked_stream = stream_opt_clone.lock().unwrap();//stream_opt.lock().unwrap().as_ref().clone();
    warn!("After locking stream in read");
    match stream.read(data) {
        Ok(_) => {
            warn!("Going to unlock stream in reads");
            return &data[..];
        },
        Err(_) => {
            error!("An error occurred, terminating connection");
            stream.shutdown(Shutdown::Both);
            return &[];
        }
    }
}

pub fn handle_message(msg: &[u8], sender: Sender<NotifyNode>) {
    let tag = msg[0];
    debug!("msg == {}", msg[0]);
    if (tag == 0){
        //Notify the main thread to start creating proof 
        trace!("In prover the tag is 0");
        sender.send(NotifyNode { buff: msg.to_vec(), notification: Notification::Start}).unwrap();
    }
    else if (tag == 2){
        //Notify the main thread to stop creating proofs
        trace!("In prover the tag is 2");
        stop_sending_proofs(&sender);            
    }
    else{
        error!("In prover the tag is NOT 0 and NOT 2: the tag is {}", tag)
    }
}





pub fn read_byte_from_file() -> u8 {
    return 0;
}

pub fn create_and_send_proof_batches(stream: &Option<TcpStream>, seed: u8, receiver: &Receiver<NotifyNode>) {
    let mut block_id: u32 = INITIAL_BLOCK_ID;  // Given parameter
    let mut position: u32 = INITIAL_POSITION;  // Given parameter
    let mut proof_batch: [u8;BATCH_SIZE] = [0;BATCH_SIZE];
    warn!("Prepared batch of proofs...");
    for mut iteration_c in 0..proof_batch.len() {
        (block_id, position) = random_path_generator(block_id, iteration_c, position, seed);
        proof_batch[iteration_c] = read_byte_from_file();
    }
    let mut response_msg: [u8; BATCH_SIZE+1] = [1; BATCH_SIZE+1];
    //the tag is 1 
    response_msg[1..].copy_from_slice(&proof_batch);
    warn!("Before send_msg_prover");
    send_msg(stream.as_ref().unwrap(), &response_msg);
    warn!("Batch of proofs sent from prover to verifier");
}