use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, Shutdown, TcpStream};
use std::option;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc::{Sender, self};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::channel;
use std::thread::{self, Thread};

use aes::Block;
use log::{info, error, debug, trace, warn};

use crate::block_generation::encoder::generate_block;
use crate::block_generation::utils::Utils::{MAX_NUM_PROOFS, BATCH_SIZE, INITIAL_BLOCK_ID, INITIAL_POSITION, NUM_BLOCK_PER_UNIT};
use crate::communication::client::send_msg;
use crate::communication::handle_prover::random_path_generator;
use crate::communication::structs::Notification;
use crate::communication::{structs::Phase};
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
        let sender: Sender<Notification>;
        let receiver: Receiver<Notification>;
        (sender,receiver) = mpsc::channel();

        let mut verifier = Prover::new(address, prover_address, sender);

        info!("Prover starting main_handler()");
        verifier.main_handler(&receiver);
    }

    pub fn new(address: String, verifier_address: String, sender: Sender<Notification>) -> Prover {
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
        let mut file = File::create("serailized_file.bin").unwrap();
        //file.write_all(&encoded)?;
        file.write_all(&enc_slice);
        let mut stream: Option<TcpStream> = None;
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
    
    pub fn start_server(&mut self, sender: Sender<Notification>) {
        info!("Prover server listening on address {}", self.address);
        let listener = TcpListener::bind(&self.address).unwrap();
        let mut stream = listener.accept().unwrap().0;
        self.stream_opt = Some(stream.try_clone().unwrap());
        thread::spawn(move || {
            loop{
                //trace!("Started loop in prover");
                let sender_clone = sender.clone();
                let mut stream_clone = stream.try_clone().unwrap();
                //info!("New connection: {}", stream.peer_addr().unwrap());
                let mut data = [0; 128]; // Use a smaller buffer size
                let retrieved_data = handle_stream(&mut stream_clone, &mut data);
                handle_message(&mut stream_clone, retrieved_data, sender_clone);
            }
        });
    }

    pub fn main_handler(&self, receiver: &mpsc::Receiver<Notification>) {
        let mut counter = 0;
        let mut started = false;
        while counter < MAX_NUM_PROOFS {
            match receiver.try_recv() {  //PROBLEMA: QUA SI FERMA SEMPRE. MI SERVIREBBE UNA NOTIFICA CONTINUE A OGNI CICLO. INVECE IO VORREI UNA NOTIFICA STOP QUANDO SERVE E NEL RESTO DEL TEMPO RIMANE CONTINUE
                Ok(notification) => {
                    match notification {
                        Notification::Start => {
                            info!("unexpected Continue notification received");
                            create_and_send_proof_batches(&self.stream_opt.as_ref().unwrap(), self.seed, &receiver);
                            //QUI USA IL BUFFER RICEVUTO A FAI UPDATE DEL SEED NEL SELF



                            started = true;
                        }
                        Notification::Stop => {
                            info!("Received Stop signal: the prover stopped sending proof batches");
                            break;
                        }
                        Notification::Verification => {warn!("unexpected Continue notification received")}
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    //AGGIORNARE AGGIUNGENDO STREAM E SEED COME MEMBRI. INOLTRE AGGIORNARLI QUANDO NECESSARIO
                    create_and_send_proof_batches(&self.stream_opt.as_ref().unwrap(), self.seed, &receiver);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    error!("The prover has been disconnected");
                    break;
                }
            }
            counter += BATCH_SIZE*10;
        }
    }
}

pub fn stop_sending_proofs(sender: mpsc::Sender<Notification>) {
    sender.send(Notification::Stop).unwrap();
}



pub fn handle_stream<'a>(stream: &mut TcpStream, data: &'a mut [u8]) -> &'a[u8] {
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

pub fn handle_message(stream: &mut TcpStream, msg: &[u8], sender: Sender<Notification>) {
    let tag = msg[0];
    if (tag == 0){
        //ALLA FINE MANDA NOTIFYNODE ANCHE QUI E IN START ALLEGACI IL BUFFER COL SEED.
        //POI IN main_handler RICORDA DI FARE UPDATE DEL SEED IN SELF
        sender.send(Notification::Start).unwrap();
    }
    else if (tag == 2){
        trace!("In prover the tag is 2");
        stop_sending_proofs(sender);            
    }
    else{
        trace!("In prover the tag is NOT 1 and NOT 2");
        error!("Received wrong tag: this is a Prover, the tag is {}", tag)
    }
}








pub fn read_byte_from_file() -> u8 {
    return 0;
}

pub fn create_and_send_proof_batches(stream: &TcpStream, seed: u8, receiver: &mpsc::Receiver<Notification>) {
    let mut block_id: u32 = INITIAL_BLOCK_ID;  // Given parameter
    let mut position: u32 = INITIAL_POSITION;  //Given parameter
    let mut proof_batch: [u8;BATCH_SIZE] = [0;BATCH_SIZE];
    info!("Prepared batch of proofs...");
    for mut iteration_c in 0..proof_batch.len() {
        (block_id, position) = random_path_generator(block_id, iteration_c, position, seed);
        proof_batch[iteration_c] = read_byte_from_file();
    }
    let mut response_msg: [u8; BATCH_SIZE+1] = [1; BATCH_SIZE+1];
    //the tag is 1 
    response_msg[1..].copy_from_slice(&proof_batch);
    let my_slice: &[u8] = &response_msg;
    debug!("IN PROVER MSG[0] ==  {}",my_slice[0]);
    send_msg(&stream, &response_msg);

    info!("Batch of proofs sent from prover at {} to the verifier at address {}",
            stream.local_addr().unwrap().to_string(),stream.peer_addr().unwrap().to_string());
}