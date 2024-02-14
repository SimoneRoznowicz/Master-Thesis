use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::{Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use std::vec;

use log::{debug, error, info, trace, warn};

use crate::block_generation::blockgen::{
    FragmentGroup, GROUP_BYTE_SIZE,
};
use crate::block_generation::decoder::{decode, reconstruct_raw_data};
use crate::block_generation::encoder::{encode, generate_xored_data};
use crate::block_generation::utils::Utils::{
    BATCH_SIZE, BUFFER_DATA_SIZE, HASH_BYTES_LEN, INITIAL_BLOCK_ID,
    INITIAL_POSITION, NUM_BYTES_IN_BLOCK_GROUP,
    NUM_BYTES_PER_BLOCK_ID, NUM_BYTES_PER_POSITION,
};
use crate::communication::client::send_msg;
use crate::communication::path_generator::random_path_generator;
use crate::communication::structs::{Notification, NotifyNode};
use crate::Merkle_Tree::structs::{Direction, Proof, Sibling};

use super::utils::from_proof_to_bytes;

#[derive(Debug)]
pub struct Prover {
    address: String,
    stream_opt: Option<TcpStream>,
    seed: u8,
    iteration: u64,
    shared_file: Arc<Mutex<File>>,
}

impl Prover {

    //Entry point to execute a Prover instance
    pub fn start(address: String) {
        //channel to allow the verifier threads communicate with the main thread
        let sender: Sender<NotifyNode>;
        let receiver: Receiver<NotifyNode>;
        (sender, receiver) = channel();

        let mut verifier = Prover::new(address, sender);

        info!("Prover starting main_handler()");
        verifier.main_handler(&receiver);
    }

    pub fn new(address: String, sender: Sender<NotifyNode>) -> Prover {
        debug!("beginning of new Prover");
        let mut files_to_remove = vec![
            "test_main.bin",
            "output.txt",
            "output.bin",
            "reconstructed.mp4",
            "generated_almost_empty_out.txt",
        ];
        for file_path in files_to_remove {
            match fs::remove_file(file_path) {
                Ok(()) => {
                    println!("File {} removed successfully.", file_path);
                }
                Err(err) => {
                    eprintln!("Error removing file {}: {:?}", file_path, err);
                }
            }
        }

        let mut input_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("input.mp4")
            .unwrap();

        let mut output_file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open("output.bin")
            .unwrap();

        //uncomment to reconstruct the input file from output file 
        // let mut reconstructed_file = OpenOptions::new()
        //     .create(true)
        //     .write(true)
        //     .read(true)
        //     .open("reconstructed.mp4").unwrap();

        let mut root_hashes = Vec::new();

        match encode(
            input_file.try_clone().unwrap(),
            &output_file,
            &mut root_hashes,
        ) {
            Ok(_) => {
                info!("Correctly encoded")
            }
            Err(e) => {
                error!("Error while encoding: {:?}", e)
            }
        };

        // match decode(&output_file, &reconstructed_file, &root_hashes) {
        //     Ok(_) => {info!("Correctly decoded")},
        //     Err(e) => {error!("Error while decoding: {:?}",e)},
        // };

        let metadata = input_file.metadata();
        debug!("input-img len = {}", metadata.unwrap().len());

        let input_lenght = input_file.seek(SeekFrom::End(0));
        debug!("input-img  == {:?}", input_lenght);

        input_file.seek(SeekFrom::Start(0));

        let mut time_block_creation: Vec<u128> = Vec::new();
        let shared_file = Arc::new(Mutex::new(output_file));


        //RECONSTRUCT RAW DATA
        let mut buffer = vec![0; HASH_BYTES_LEN + NUM_BYTES_IN_BLOCK_GROUP as usize];
        read_hash_and_block_from_output_file(&shared_file, 0, &mut buffer);
        let reconstructed_buffer = reconstruct_raw_data(0, &buffer);

        let sum_time_blocks_creation: u128 = time_block_creation.iter().sum();
        debug!(
            "Average time passed for 4 blocks creation is {:?}",
            sum_time_blocks_creation as f64 / (1000.0 * time_block_creation.len() as f64)
        );

        let stream: Option<TcpStream> = None;
        let mut this = Self {
            address,
            stream_opt: stream,
            seed: 0, //default value
            iteration: 0,
            shared_file,
        };

        this.start_server(sender);

        this
    }

    /*
     * Server implementation: the prover keeps listening on the tcpstream endpoint. When a new message is detected,
     * it is handled separely in the handle_message function.
     */
    pub fn start_server(&mut self, sender: Sender<NotifyNode>) {
        info!("Prover server listening on address {}", self.address);
        let listener = TcpListener::bind(&self.address).unwrap();
        let stream = listener.accept().unwrap().0;
        self.stream_opt = Some(stream.try_clone().unwrap());

        thread::spawn(move || {
            loop {
                let sender_clone = sender.clone();
                let mut stream_clone = stream.try_clone().unwrap();
                let mut data = vec![0; BUFFER_DATA_SIZE]; // Use a smaller buffer size
                let retrieved_data = handle_stream(&mut stream_clone, &mut data);
                handle_message(retrieved_data, sender_clone);
            }
        });
    }

    /*
    * This is the job scheduler of the verifier.
    */
    pub fn main_handler(&mut self, receiver: &Receiver<NotifyNode>) {
        let _counter = 0;
        let mut is_started = false;
        loop {
            match receiver.try_recv() {
                Ok(notify_node) => match notify_node.notification {
                    Notification::Collect_Block_Hashes => {
                        self.commit_to_data();
                    }
                    Notification::Start => {
                        is_started = true;
                        info!("Start Notification received");
                        self.seed = notify_node.buff[1];

                        (self.seed, self.iteration) = create_and_send_proof_batches(
                            &self.stream_opt,
                            self.seed,
                            &receiver,
                            &self.shared_file,
                            self.iteration,
                        );
                    }
                    Notification::Stop => {
                        info!("Received Stop signal: the prover stopped sending proof batches");
                        is_started = false;
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
                        (self.seed, self.iteration) = create_and_send_proof_batches(
                            &self.stream_opt,
                            self.seed,
                            &receiver,
                            &self.shared_file,
                            self.iteration,
                        );
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    error!("The prover has been disconnected");
                    break;
                }
            }
        }
    }

    /*
    * The prover commits to some raw data for the whole duration of the protocol execution: it generates the hash root of each block.
    */
    pub fn commit_to_data(&mut self) {
        //save all hashes in 1 vector. Send the vector
        let mut offset_start_hash: usize = 8; //first 8 bytes are the hash of the whole input file
        let mut data_block_hashes = vec![8]; //tag 8 == receiving block hashes
        let metadata;
        {
            metadata = self.shared_file.lock().unwrap().metadata();
        }
        let file_len = metadata.unwrap().len();
        while offset_start_hash < file_len as usize {
            data_block_hashes.extend(read_hashes_from_file(
                &self.shared_file,
                offset_start_hash as u64,
            ));
            offset_start_hash += HASH_BYTES_LEN + NUM_BYTES_IN_BLOCK_GROUP as usize;
        }
        debug!("PROVER: BLOCKS MAP == {:?}", data_block_hashes);

        send_msg(&self.stream_opt.as_ref().unwrap(), &data_block_hashes);
    }

    /*
    * The prover starts creates all the necessary inclusion proofs: for every (block_id,position) generate an inclusion proof
    * This means the raw data is retrieved and the Merkle Tree is created. 
    * Finally each Inclusion Proof is generated as in the steps for the Correctnes Verification discussed in the thesis 
    */
    pub fn create_inclusion_proofs(&mut self, msg: &[u8]) {
        info!("Started creating Inclusion Proofs");
        let mut block_ids_positions: HashSet<(u32, u32)> = HashSet::new(); //k: iteration; v:(block_id,position)

        let mut i = 1;
        // Retrieve block_ids and positions from msg by the verifier
        let mut k = 0;
        while i < msg.len() {
            let mut index_array: [u8; NUM_BYTES_PER_BLOCK_ID] = [0; NUM_BYTES_PER_BLOCK_ID];
            index_array.copy_from_slice(&msg[i..i + NUM_BYTES_PER_BLOCK_ID]);
            let retrieved_block_id = u32::from_le_bytes(index_array);
            // block_ids.push(retrieved_block_id);
            debug!(
                "indxx == {} and retrieved_block_id == {}",
                i, retrieved_block_id
            );

            let mut position_array: [u8; NUM_BYTES_PER_POSITION] = [0; NUM_BYTES_PER_POSITION];
            position_array.copy_from_slice(
                &msg[i + NUM_BYTES_PER_BLOCK_ID
                    ..i + NUM_BYTES_PER_BLOCK_ID + NUM_BYTES_PER_POSITION],
            );
            let retrieved_pos = u32::from_le_bytes(position_array);
            debug!("indxx == {} and retrieved_pos == {}", i, retrieved_pos);
            // positions.push(retrieved_pos);

            block_ids_positions.insert((retrieved_block_id, retrieved_pos));

            k += 1;
            i += NUM_BYTES_PER_BLOCK_ID + NUM_BYTES_PER_POSITION;
        }
        debug!("block_ids_positions == {:?}", block_ids_positions);

        // Generate and send all the requested Inclusion Proofs:
        debug!("Generate Merkle Trees and send each created inclusion proofs");

        for elem in block_ids_positions {
            let mut buffer = vec![0; HASH_BYTES_LEN + NUM_BYTES_IN_BLOCK_GROUP as usize];
            read_hash_and_block_from_output_file(&self.shared_file, elem.0, &mut buffer);

            let mut number_id_fragment = elem.0 / HASH_BYTES_LEN as u32;
            let mut indx_start = (number_id_fragment) as usize * HASH_BYTES_LEN; //layer_len % HASH_BYTES_LEN;

            debug!(
                "original xored_data_in_prover == {:?}",
                buffer[HASH_BYTES_LEN + indx_start as usize
                    ..HASH_BYTES_LEN * 2 + indx_start as usize]
                    .to_vec()
            );

            let reconstructed_buffer = reconstruct_raw_data(elem.0 as u64, &buffer);

            let (proof, self_fragment, root_hash) =
                generate_MT_vector(&reconstructed_buffer, elem.0, elem.1);

            let generated_xored_data_in_prover =
                generate_xored_data(elem.0, elem.1, root_hash, self_fragment, false);
            debug!(
                "generated_xored_data_in_prover == {:?}",
                generated_xored_data_in_prover
            );

            let mut bytes_proof = Vec::new();
            from_proof_to_bytes(proof, &mut bytes_proof); //cambia poi la funzione cosi ricevi come input &proof

            let mut msg = vec![4]; // tag == 4 -> Handle Inclusion Proof
            msg.extend_from_slice(&root_hash); //HASH
            msg.extend_from_slice(&elem.0.to_le_bytes()); //block_id
            msg.extend_from_slice(&elem.1.to_le_bytes()); //byte_position
            msg.extend_from_slice(&self_fragment); //self_fragment
            msg.extend_from_slice(&bytes_proof); //proof

            send_msg(&self.stream_opt.as_ref().unwrap(), &msg);
        }
    }
}

pub fn handle_stream<'a>(stream: &mut TcpStream, data: &'a mut [u8]) -> &'a [u8] {
    match stream.read(data) {
        Ok(size) => {
            return &data[..size];
        }
        Err(_) => {
            error!("An error occurred, terminating connection");
            stream.shutdown(Shutdown::Both);
            return &[];
        }
    }
}

/*
* If the prover is correct, when it is challenged, it keeps collecting proofs by reading 
* in the output file based on the (block id,position) computed in the random path algorithm.
* New batches of proofs are continuously generated, until a stop message is received.
*/
pub fn create_and_send_proof_batches(
    stream: &Option<TcpStream>,
    mut seed: u8,
    _receiver: &Receiver<NotifyNode>,
    file: &Arc<Mutex<File>>,
    mut iteration: u64,
) -> (u8, u64) {
    let mut block_id: u32 = INITIAL_BLOCK_ID; // Given parameter
    let mut position: u32 = INITIAL_POSITION; // Given parameter
    let mut proof_batch: [u8; BATCH_SIZE] = [0; BATCH_SIZE];
    debug!("Preparing batch of proofs.");
    let init_iteration = iteration;
    while iteration < init_iteration + proof_batch.len() as u64 {
        (block_id, position, seed) = random_path_generator(seed, iteration);

        proof_batch[(iteration - init_iteration) as usize] =
            read_byte_from_file(file, block_id, position);

        iteration += 1;
    }

    let mut response_msg: [u8; BATCH_SIZE + 1] = [1; BATCH_SIZE + 1];
    //the tag is 1
    response_msg[1..].copy_from_slice(&proof_batch);
    debug!("Before send_msg_prover");
    send_msg(stream.as_ref().unwrap(), &response_msg);

    return (seed, iteration);
}

/*
* The function is used to generate the MT in one vector.
* Additionally, it retrieves the root hash and the fragment (self_fragment) corresponding to the byte for which an Inclusion Proof is generated.
*/
pub fn generate_MT_vector(
    buffer: &Vec<u8>,
    block_id: u32,
    position: u32,
) -> (Proof, [u8; 32], [u8; 32]) {

    let mut hash_layers: Vec<u8> = buffer.to_vec();
    let mut root_hash: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];

    let mut number_id_fragment = position / HASH_BYTES_LEN as u32;
    let mut fragment_start_indx = (number_id_fragment) as usize * HASH_BYTES_LEN;
    debug!("fragment_start_indx is {}", fragment_start_indx);

    let mut i = 0;
    let _counter = 0;
    while i + HASH_BYTES_LEN < hash_layers.len() {
        let mut first_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        first_fragment.copy_from_slice(&hash_layers[i..i + HASH_BYTES_LEN]);

        let mut second_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        second_fragment.copy_from_slice(&hash_layers[i + HASH_BYTES_LEN..i + HASH_BYTES_LEN * 2]);

        if i < buffer.len() {
            first_fragment = *blake3::hash(&first_fragment).as_bytes();
            second_fragment = *blake3::hash(&second_fragment).as_bytes();
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&first_fragment);
        hasher.update(&second_fragment);
        let new_hash = hasher.finalize();

        hash_layers.extend(new_hash.as_bytes());

        i = i + HASH_BYTES_LEN * 2;
    }

    root_hash.copy_from_slice(&hash_layers[hash_layers.len() - HASH_BYTES_LEN..]);

    let mut counter = 0;
    let mut flag = false;
    let mut lay_len = buffer.len();
    debug!("Hash_layers == {:?}", hash_layers.len());
    for b in &hash_layers {
        let mut ccstr = b.to_string() + ", ";
        if counter % HASH_BYTES_LEN == 0 {
            ccstr = String::from("*\n") + &ccstr;
        }
        if counter == lay_len {
            ccstr = ccstr + "\n--> " + &lay_len.to_string() + "\n";
            flag = true;
        }

        if counter == lay_len {
            counter = 0;
            lay_len = lay_len / 2;
        }
        counter += 1;
    }
    debug!("root_hash == {:?}", root_hash);
    let _i = 0;
    let mut layer_len = buffer.len();
    let mut siblings = Vec::new();

    let mut layer_counter = buffer.len();
    let mut self_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
    let mut is_first_iter = true;
    debug!("position == {}", position);

    let mut count_frag = layer_len / HASH_BYTES_LEN;

    while layer_len / HASH_BYTES_LEN > 1 {
        //last layer before root
        debug!("layer_len == {}", layer_len);
        debug!("layer_counter == {}", layer_counter);
        debug!(
            "number fragment == {} over {} fragments",
            number_id_fragment,
            layer_len / HASH_BYTES_LEN
        );
        debug!("count_frag == {}", count_frag);
        debug!("fragment_indx start == {}", fragment_start_indx);
        let mut sibling_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];

        let direction_sibling;
        if number_id_fragment % 2 == 0 {
            direction_sibling = Direction::Right;
            sibling_fragment.copy_from_slice(
                &hash_layers[fragment_start_indx + HASH_BYTES_LEN
                    ..fragment_start_indx + HASH_BYTES_LEN * 2],
            );
        } else {
            direction_sibling = Direction::Left;
            sibling_fragment.copy_from_slice(
                &hash_layers[(fragment_start_indx - HASH_BYTES_LEN)..fragment_start_indx],
            );
        }

        if is_first_iter {
            sibling_fragment = *blake3::hash(&sibling_fragment).as_bytes();
        }
        siblings.push(Sibling::new(
            blake3::Hash::from_bytes(sibling_fragment),
            direction_sibling,
        ));

        if is_first_iter {
            is_first_iter = false;
            self_fragment.copy_from_slice(
                &hash_layers[fragment_start_indx..fragment_start_indx + HASH_BYTES_LEN],
            );
        }

        layer_len = layer_len / 2;
        number_id_fragment = number_id_fragment / 2;
        count_frag = layer_counter / HASH_BYTES_LEN + number_id_fragment as usize;
        layer_counter += layer_len;
        fragment_start_indx = (count_frag) * HASH_BYTES_LEN;
    }
    let self_fragment_hash = blake3::hash(&self_fragment);
    debug!(
        "Self_fragment xxx == {:?}\nSelf_fragment hash == {:?}",
        self_fragment, self_fragment_hash
    );
    debug!("Siblings length == {:?}", siblings.len());

    return (Proof::new(siblings), self_fragment, root_hash);

    //                    A
    //            A               a             is index % 2 == 0 --> No then take sibling on the R
    //        a       A       a       a         is index % 2 == 0 --> No then take sibling on the L
    //      a   a   A   a   a   a   a   a       is index % 2 == 0 --> Yes then take sibling on the R
    //     a a a a a A a a a a a a a a a a
    //                                          Next level position di A is index = index / 2
    //                                          At every new level, • Identify the reference position of A: the sibling is either on the left or on the right of A
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

pub fn send_collect_block_hashes(sender: &Sender<NotifyNode>) {
    match sender.send(NotifyNode {
        buff: Vec::new(),
        notification: Notification::Collect_Block_Hashes,
    }) {
        Ok(_) => {}
        Err(_) => {
            warn!("This Collect_Block_Hashes Notification was not received")
        }
    };
}

pub fn read_byte_from_file(
    shared_input_file: &Arc<Mutex<File>>,
    block_id: u32,
    position: u32,
) -> u8 {
    let mut file = shared_input_file.lock().unwrap();
    let index = (block_id * NUM_BYTES_IN_BLOCK_GROUP) as u64
        + position as u64
        + 8
        + HASH_BYTES_LEN as u64 * (block_id + 1) as u64;

    let metadata = file.metadata();
    debug!("block_id == {} while position == {}", block_id, position);
    debug!(
        "index == {} while file is long {}",
        index,
        metadata.unwrap().len()
    );

    file.seek(SeekFrom::Start(index)).unwrap();

    let mut start_t = Instant::now();
    let mut buffer = [0; 1];
    match file.read_exact(&mut buffer) {
        Ok(_) => {}
        Err(e) => {
            error!("Error reading file == {:?}", e)
        }
    };
    let mut end_t = Instant::now();
    debug!(
        "Time to read 1 byte in micro seconds: {}",
        (end_t - start_t).as_micros()
    );
    return buffer[0];
}

pub fn read_hash_and_block_from_output_file(
    shared_file: &Arc<Mutex<File>>,
    block_id: u32,
    buffer: &mut [u8],
) -> Vec<u8> {
    let mut file = shared_file.lock().unwrap();
    let index =
        (block_id * NUM_BYTES_IN_BLOCK_GROUP) as u64 + 8 + HASH_BYTES_LEN as u64 * block_id as u64;

    file.seek(SeekFrom::Start(index)).unwrap();

    match file.read_exact(buffer) {
        Ok(_) => {}
        Err(e) => {
            error!("Error reading file == {:?}", e)
        }
    };

    return buffer.to_vec();
}

pub fn read_block_from_input_file(file: &mut File, block_id: u32, buffer: &mut [u8]) -> Vec<u8> {
    let index = (block_id * NUM_BYTES_IN_BLOCK_GROUP) as u64;

    file.seek(SeekFrom::Start(index)).unwrap();

    match file.read_exact(buffer) {
        Ok(_) => {}
        Err(e) => {
            error!("Error reading file == {:?}", e)
        }
    };

    return buffer.to_vec();
}

pub fn read_hashes_from_file(shared_file: &Arc<Mutex<File>>, indx: u64) -> [u8; HASH_BYTES_LEN] {
    let mut file = shared_file.lock().unwrap();

    file.seek(SeekFrom::Start(indx)).unwrap();

    let mut buffer = [0; HASH_BYTES_LEN];
    match file.read_exact(&mut buffer) {
        Ok(_) => {}
        Err(e) => {
            error!("Error reading file: == {:?}", e)
        }
    };
    return buffer;
}

/*
* Generate a NotifyNode specific for each tag received. This NotifyNode will be received by the
* main_handler function that will take action according to the related message
*/
pub fn handle_message(msg: &[u8], sender: Sender<NotifyNode>) {
    if !msg.is_empty() {
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
        } else if tag == 7 {
            //Notify the main thread to start creating inclusion proofs
            trace!("In prover the tag is 7");
            send_collect_block_hashes(&sender);
        } else {
            error!("In prover the tag is NOT 0 and NOT 2: the tag is {}", tag)
        }
    }
}
