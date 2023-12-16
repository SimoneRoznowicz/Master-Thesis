use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpListener, TcpStream};


use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::{Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self};


use log::{debug, error, info, trace, warn};
use serde_json::error;
// use first_rust_project::src;

use crate::block_generation::blockgen::{FragmentGroup, GROUP_SIZE};
use crate::block_generation::encoder::generate_block_group;
use crate::block_generation::utils::Utils::{
    BATCH_SIZE, INITIAL_BLOCK_ID, INITIAL_POSITION, NUM_BLOCK_GROUPS_PER_UNIT,
    NUM_BYTES_PER_BLOCK_ID, NUM_BYTES_PER_POSITION, NUM_BYTES_IN_BLOCK,
};
use crate::communication::client::{send_msg};
use crate::communication::handle_prover::random_path_generator1;
use crate::communication::structs::Notification;
use crate::Merkle_Tree::mpt::MerkleTree;


use super::structs::NotifyNode;
use super::utils::from_proof_to_bytes;


#[derive(Debug)]
pub struct Prover {
    address: String,
    verifier_address: String,
    stream_opt: Option<TcpStream>,
    //unit: Vec<FragmentGroup>,   //PROVVISORIO: POI VOGLIO AVERE SOLO UN FILE
    seed: u8,
    iteration: u32,
    shared_file: Arc<Mutex<File>>,
}

impl Prover {
    pub fn start(address: String, prover_address: String) {
        //channel to allow the verifier threads communicate with the main thread
        let sender: Sender<NotifyNode>;
        let receiver: Receiver<NotifyNode>;
        (sender, receiver) = channel();

        let mut verifier = Prover::new(address, prover_address, sender);

        info!("Prover starting main_handler()");
        verifier.main_handler(&receiver);
    }

    pub fn new(address: String, verifier_address: String, sender: Sender<NotifyNode>) -> Prover {
        debug!("beginning of new Prover");
        let mut unit: Vec<FragmentGroup> = Vec::new();

        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .write(true)
            .open("test_main.bin")
            .unwrap();

        let shared_file = Arc::new(Mutex::new(new_file));
        {
            //File of total length (2^21)*(NUM_BLOCK_GROUPS_PER_UNIT) 
            let mut file = shared_file.lock().unwrap();
            for i in 0..NUM_BLOCK_GROUPS_PER_UNIT {
                let block_group = generate_block_group(i);
                debug!("4 Blocks generated");
                for i in 0..GROUP_SIZE {  
                    for j in 0..block_group.len() {
                        let byte_fragment = block_group[j][i].to_le_bytes();
                        file.write_all(&byte_fragment).unwrap();
                    }
                }
            }  
            let mut metadata = file.metadata();
            warn!("Length file == {}", metadata.unwrap().len());
        }
        // file.seek(SeekFrom::Start(0)).unwrap();

        // let mut buffer = Vec::new();
        // match shared_file.read_to_end(&mut buffer) {
        //     Ok(_) => {},
        //     Err(e) => {info!("error == {:?}", e)},
        // };

        let mut encoded: Vec<u8> = bincode::serialize(&unit).unwrap();
        let _enc_slice: &[u8] = encoded.as_mut_slice();

        let stream: Option<TcpStream> = None;
        let mut this = Self {
            address,
            verifier_address,
            stream_opt: stream,
            seed: 0, //default value
            iteration: 0,
            shared_file,
        };

        this.start_server(sender);

        this
    }

    pub fn start_server(&mut self, sender: Sender<NotifyNode>) {
        info!("Prover server listening on address {}", self.address);
        let listener = TcpListener::bind(&self.address).unwrap();
        let mut stream = listener.accept().unwrap().0;
        self.stream_opt = Some(stream.try_clone().unwrap());

        thread::spawn(move || {
            loop {
                //secondo me in qualche modo non rilascia qua
                let sender_clone = sender.clone();
                let mut stream_clone = stream.try_clone().unwrap();
                // //info!("New connection: {}", stream.peer_addr().unwrap());
                let mut data = [0; 128]; // Use a smaller buffer size
                let retrieved_data = handle_stream(&mut stream_clone, &mut data);
                handle_message(retrieved_data, sender_clone);
            }
        });
    }

    pub fn main_handler(&mut self, receiver: &Receiver<NotifyNode>) {
        let _counter = 0;
        let mut is_started = false;
        // while counter < MAX_NUM_PROOFS {
        loop {
            match receiver.try_recv() {
                //PROBLEMA: QUA SI FERMA SEMPRE. MI SERVIREBBE UNA NOTIFICA CONTINUE A OGNI CICLO. INVECE IO VORREI UNA NOTIFICA STOP QUANDO SERVE E NEL RESTO DEL TEMPO RIMANE CONTINUE
                Ok(notify_node) => match notify_node.notification {
                    Notification::Start => {
                        is_started = true;
                        info!("Start Notification received");
                        self.seed = notify_node.buff[1];
                        info!("buff AT THE START == {:?}", notify_node.buff);

                        (self.seed,self.iteration) = create_and_send_proof_batches(
                            &self.stream_opt,
                            self.seed,   //DEFAULT HASH
                            &receiver,
                            &self.shared_file,
                            self.iteration,
                        );
                    }
                    Notification::Stop => {
                        info!("Received Stop signal: the prover stopped sending proof batches");
                        break;
                    }
                    Notification::Create_Inclusion_Proofs => {
                        self.create_inclusion_proofs(&notify_node.buff);
                    }
                    _ => {
                        error!(
                            "Unexpected notification received: {:?}",
                            notify_node.notification
                        )
                    }
                },
                Err(TryRecvError::Empty) => {
                    if is_started {
                        (self.seed,self.iteration) = create_and_send_proof_batches(  
                            &self.stream_opt,
                            self.seed,    
                            &receiver,
                            &self.shared_file,
                            self.iteration,
                        );
                    }
                    info!("In TryRecvError::Empty send batches");
                }
                Err(TryRecvError::Disconnected) => {
                    error!("The prover has been disconnected");
                    break;
                }
            }
            //counter += BATCH_SIZE*10;
        }
        info!("ARRIVED AT END OF LOOP");
    }

    pub fn create_inclusion_proofs(&mut self, msg: &[u8]) {
        let mut block_ids: Vec<u32> = Vec::new();
        let mut positions: Vec<u32> = Vec::new();
        let mut i = 1;
        // Retrieve block_ids and positions from msg by the verifier
        while i < msg.len() {
            let mut index_array: [u8; NUM_BYTES_PER_BLOCK_ID] = [0; NUM_BYTES_PER_BLOCK_ID];
            index_array.copy_from_slice(&msg[i..i + NUM_BYTES_PER_BLOCK_ID]);
            let retrieved_block_id = u32::from_le_bytes(index_array);
            block_ids.push(retrieved_block_id);

            let mut position_array: [u8; NUM_BYTES_PER_POSITION] = [0; NUM_BYTES_PER_POSITION];
            position_array.copy_from_slice(
                &msg[i + NUM_BYTES_PER_BLOCK_ID
                    ..i + NUM_BYTES_PER_BLOCK_ID + NUM_BYTES_PER_POSITION],
            );
            let retrieved_pos = u32::from_le_bytes(position_array);
            positions.push(retrieved_pos);

            i += NUM_BYTES_PER_BLOCK_ID + NUM_BYTES_PER_POSITION;
        }

        // Generate and send all the requested Inclusion Proofs:
        // Send a buffer containing in order: tag, hash and proof
        for (indx, block_id) in block_ids.iter().enumerate() {
            //send root_hash + proof
            let mut merkle_tree = self.generate_merkle_tree(*block_id);
            let proof = merkle_tree.prove(positions[indx]);

            let bytes_proof = from_proof_to_bytes(proof); //cambia poi la funzione cosi ricevi come input &proof
            let hash = merkle_tree.compute_hashes();

            let mut msg = vec![4]; // tag == 4 -> Handle Inclusion Proof
            msg.extend_from_slice(&hash.to_bytes());
            msg.extend_from_slice(&bytes_proof);

            send_msg(&self.stream_opt.as_ref().unwrap(), &msg);
        }
    }

    pub fn generate_merkle_tree(&mut self, block_id: u32) -> MerkleTree<u32, u8> {
        let mut merkle_tree = MerkleTree::<u32, u8>::new();
        let mut file = self.shared_file.lock().unwrap();
        file.seek(SeekFrom::Start(block_id as u64 * 32 - 1))
            .unwrap(); //beginning of the block number block_id
        for i in 0..32 {
            let mut buffer = [0; 1];
            file.read_exact(&mut buffer).unwrap();
            merkle_tree.insert(i, buffer[0]); //Given a block: Key -> position (offset) of the byte in the block; Value -> value of the considered byte
        }
        return merkle_tree;
    }
}

pub fn handle_stream<'a>(stream: &mut TcpStream, data: &'a mut [u8]) -> &'a [u8] {
    // let mut stream_opt_clone = stream_opt.clone();
    // let mut locked_stream = stream_opt_clone.lock().unwrap();//stream_opt.lock().unwrap().as_ref().clone();
    match stream.read(data) {
        Ok(_) => {
            return &data[..];
        }
        Err(_) => {
            error!("An error occurred, terminating connection");
            stream.shutdown(Shutdown::Both);
            return &[];
        }
    }
}

pub fn create_and_send_proof_batches(
    stream: &Option<TcpStream>,
    mut seed: u8,
    _receiver: &Receiver<NotifyNode>,
    file: &Arc<Mutex<File>>,
    mut iteration: u32,
) -> (u8,u32) {
    let mut block_id: u32 = INITIAL_BLOCK_ID; // Given parameter
    let mut position: u32 = INITIAL_POSITION; // Given parameter
    let mut proof_batch: [u8; BATCH_SIZE] = [0; BATCH_SIZE];
    debug!("Preparing batch of proofs.");
    error!("SEED == {}", seed);
    let initIteration = iteration;
    while(iteration < initIteration+proof_batch.len() as u32){
        //PUOI USARE SEMPRE SOLO IL SEED INVECE DI USARE ANCHE block_id, iteration_c, position
        (block_id, position, seed) = random_path_generator1(seed,iteration as u8);
        proof_batch[(iteration-initIteration)as usize] = read_byte_from_file(file, block_id, position);
        error!("seed == {}", seed);
        iteration+=1;
    }

    let mut response_msg: [u8; BATCH_SIZE + 1] = [1; BATCH_SIZE + 1];
    //the tag is 1
    response_msg[1..].copy_from_slice(&proof_batch);
    debug!("Before send_msg_prover");
    send_msg(stream.as_ref().unwrap(), &response_msg);
    debug!("Batch of proofs sent from prover to verifier");
    return (seed,iteration);
}

pub fn send_stop_notification(sender: &Sender<NotifyNode>) {
    match sender.send(NotifyNode {
        buff: Vec::new(),
        notification: Notification::Stop,
    }) {
        Ok(_) => {}
        Err(_) => {
            warn!("This stop Notification was not received")
        }
    };
}

pub fn send_start_notification(msg: &[u8], sender: &Sender<NotifyNode>) {
    match sender.send(NotifyNode {
        buff: msg.to_vec(),
        notification: Notification::Start,
    }) {
        Ok(_) => {}
        Err(_) => {
            warn!("This start Notification was not received")
        }
    };
}

pub fn send_create_inclusion_proofs(msg: &[u8], sender: &Sender<NotifyNode>) {
    match sender.send(NotifyNode {
        buff: msg.to_vec(),
        notification: Notification::Create_Inclusion_Proofs,
    }) {
        Ok(_) => {}
        Err(_) => {
            warn!("This Create_Inclusion_Proofs Notification was not received")
        }
    };
}

pub fn handle_message(msg: &[u8], sender: Sender<NotifyNode>) {
    let tag = msg[0];
    debug!("msg == {}", msg[0]);
    if tag == 0 {
        //Notify the main thread to start creating proof
        trace!("In prover the tag is 0");
        send_start_notification(msg, &sender);
    } else if tag == 2 {
        //Notify the main thread to stop creating proofs
        trace!("In prover the tag is 2");
        send_stop_notification(&sender);
    } else if tag == 3 {
        //Notify the main thread to start creating inclusion proofs
        trace!("In prover the tag is 3");
        send_create_inclusion_proofs(msg, &sender);
    } else {
        error!("In prover the tag is NOT 0 and NOT 2: the tag is {}", tag)
    }
}

pub fn read_byte_from_file(shared_file: &Arc<Mutex<File>>, block_id: u32, position: u32) -> u8 {
    let mut file = shared_file.lock().unwrap();
    let index = (block_id * NUM_BYTES_IN_BLOCK) as u64 + position as u64;

    let metadata = file.metadata();
    debug!("block_id == {} while position == {}", block_id, position);
    debug!("index == {} while file is long {}", index, metadata.unwrap().len());
    
    file.seek(SeekFrom::Start(index)).unwrap();

    //Expected total size of the file: block_size*20 = ~80 Miliardi
    let mut buffer = [0; 1];
    match file.read_exact(&mut buffer) {
        Ok(_) => {}
        Err(e) => {
            error!("Error reading file == {:?}", e)
        }
    };

    return buffer[0];
}
