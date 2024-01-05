use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::{Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self};

use log::{debug, error, info, trace, warn};
use rand::seq::index;
use serde_json::error;
// use first_rust_project::src;

use crate::Merkle_Tree::client_verify::get_root_hash_mod;
use crate::block_generation::blockgen::{FragmentGroup, GROUP_SIZE, SIZE};
use crate::block_generation::encoder::generate_block_group;
use crate::block_generation::utils::Utils::{
    BATCH_SIZE, HASH_BYTES_LEN, INITIAL_BLOCK_ID, INITIAL_POSITION, NUM_BLOCK_GROUPS_PER_UNIT,
    NUM_BYTES_IN_BLOCK, NUM_BYTES_IN_BLOCK_GROUP, NUM_BYTES_PER_BLOCK_ID, NUM_BYTES_PER_POSITION,
};
use crate::communication::client::send_msg;
use crate::communication::handle_prover::random_path_generator1;
use crate::communication::structs::Notification;
use crate::Merkle_Tree::mpt::MerkleTree;
use crate::Merkle_Tree::structs::{Direction, Proof_Mod, Sibling, Sibling_Mod};

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
        let mut file2 = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .write(true)
            .open("test_main.txt")
            .unwrap();

        let shared_file = Arc::new(Mutex::new(new_file));
        {
            //File of total length (2^21)*(NUM_BLOCK_GROUPS_PER_UNIT)
            let mut file = shared_file.lock().unwrap();
            for i in 0..NUM_BLOCK_GROUPS_PER_UNIT {
                let block_group = generate_block_group(i);
                debug!("4 Blocks generated");
                let mut cc: u64 = 0;
                for i in 0..GROUP_SIZE {
                    debug!("Group Size iteration i == {}", i);
                    for j in 0..block_group.len() {
                        let byte_fragment = block_group[j][i].to_le_bytes();
                        file.write_all(&byte_fragment).unwrap();
                        // for b in byte_fragment{
                        //     if (cc % 20 == 0){
                        //         let ccstr = cc.to_string()+ "* ";
                        //         file2.write(ccstr.as_bytes());
                        //     }
                        //     let bstr = b.to_string() + " ";
                        //     file2.write(bstr.as_bytes());
                        //     cc += 1;
                        // }
                    }
                }
            }
        }

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
                let mut data = [0; 500]; // Use a smaller buffer size
                let retrieved_data = handle_stream(&mut stream_clone, &mut data);
                handle_message(retrieved_data, sender_clone);
            }
        });
    }

    pub fn main_handler(&mut self, receiver: &Receiver<NotifyNode>) {
        let counter = 0;
        let mut is_started = false;
        // while counter < MAX_NUM_PROOFS {
        loop {
            match receiver.try_recv() {
                Ok(notify_node) => match notify_node.notification {
                    Notification::Start => {
                        is_started = true;
                        info!("Start Notification received");
                        self.seed = notify_node.buff[1];
                        info!("buff AT THE START == {:?}", notify_node.buff);

                        (self.seed, self.iteration) = create_and_send_proof_batches(
                            &self.stream_opt,
                            self.seed, //DEFAULT HASH
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
            //counter += BATCH_SIZE*10;
        }
        info!("ARRIVED AT END OF LOOP");
    }

    pub fn create_inclusion_proofs(&mut self, msg: &[u8]) {
        //SO THE CREATED MESSAGE WILL BE EVENTALLY: TAG,HASH,block_id,byte_position,self_fragment,proof
        info!("Started creating Inclusion Proofs");
        let mut block_ids: Vec<u32> = Vec::new();
        let mut positions: Vec<u32> = Vec::new();
        let mut i = 1;
        // Retrieve block_ids and positions from msg by the verifier
        error!("MSG IN PROVER TO CREATE INC PROOFS == {:?}", msg);
        while i < msg.len() {
            let mut index_array: [u8; NUM_BYTES_PER_BLOCK_ID] = [0; NUM_BYTES_PER_BLOCK_ID];
            index_array.copy_from_slice(&msg[i..i + NUM_BYTES_PER_BLOCK_ID]);
            let retrieved_block_id = u32::from_le_bytes(index_array);
            block_ids.push(retrieved_block_id);
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
            positions.push(retrieved_pos);

            i += NUM_BYTES_PER_BLOCK_ID + NUM_BYTES_PER_POSITION;
        }
        debug!("block_ids == {:?}", block_ids); //Correct
        debug!("positions == {:?}", positions); //Correct

        // Generate and send all the requested Inclusion Proofs:
        // Send a buffer containing in order: tag, hash and proof
        info!("Generate Merkle Tree and send each created inclusion proofs");
        for (indx, _) in block_ids.iter().enumerate() {
            //send root_hash + proof + 32_byte_fragment

            let (proof_mod, self_fragment, root_hash) =
                generate_proof_array(&mut self.shared_file, block_ids[indx], positions[indx]);
            debug!("Self_fragment xxx outsite == {:?}",self_fragment);
            let hash_root_retrieved = get_root_hash_mod(&proof_mod, (0,0), 0, self_fragment);
            debug!("Prover: root_hash generated == {:?} \nhash_root_retrieved == {:?}",root_hash,hash_root_retrieved.as_bytes());

            //PROVA QUA A REGENERARE HASH DA QUESTA PROOF
            //let mut merkle_tree = self.generate_merkle_tree(block_ids[indx]);
            //let proof = merkle_tree.prove((block_ids[indx],positions[indx]));
            //info!("Created Merkle Tree and proof == {:?}",proof);

            let mut bytes_proof = Vec::new();
            from_proof_to_bytes(proof_mod, &mut bytes_proof); //cambia poi la funzione cosi ricevi come input &proof
                                                                  // let hash = merkle_tree.compute_hashes();

            let mut msg = vec![4]; // tag == 4 -> Handle Inclusion Proof
            msg.extend_from_slice(&root_hash); //HASH
            msg.extend_from_slice(&block_ids[indx].to_le_bytes()); //block_id
            msg.extend_from_slice(&positions[indx].to_le_bytes()); //byte_position
            msg.extend_from_slice(&self_fragment); //self_fragment
            msg.extend_from_slice(&bytes_proof); //proof

            //debug!("msg len == {:?}", msg.len());
            //debug!("msg 'creating inc proof' == {:?}", msg);
            debug!("bytes_proof len == {:?} and bytes_proof == {:?}", bytes_proof.len(), bytes_proof);

            send_msg(&self.stream_opt.as_ref().unwrap(), &msg);
            break; //TO REMOVE LATER
        }
    }

    //Merkle Tree generated based on the block_id. The proof is based on the position of the byte in the block
    pub fn generate_merkle_tree(&mut self, block_id: u32) -> MerkleTree<(u32, u32), u8> {
        let mut merkle_tree = MerkleTree::<(u32, u32), u8>::new();

        //0) Prova subiito a leggere tutti i byte da dall0inizio alla fine del blocco. Sono uno dietro laltro...
        //1) creare MTs in parallelo!! (guardare come fare ad accedere a file in lettura contemporaneamente)
        //2)
        let mut buffer = [0; NUM_BYTES_IN_BLOCK as usize];
        info!("Just before read_buffer_from_file");
        read_block_from_file(&self.shared_file, block_id, &mut buffer);
        info!(
            "Buffer[1000] == {:?} and length == {}",
            buffer[1000],
            buffer.len()
        );
        for i in 0..NUM_BYTES_IN_BLOCK {
            merkle_tree.insert((block_id, i), buffer[i as usize]); //Given a block: Key -> position (offset) of the byte in the block; Value -> value of the considered byte
            if i % 1000 == 0 {
                info!("i == {}", i);
            }
        }
        return merkle_tree;
    }
}

pub fn generate_proof_array(
    shared_file: &Arc<Mutex<File>>,
    block_id: u32,
    position: u32,
) -> (Proof_Mod, [u8; 32], [u8; 32]) {
    let mut buffer: [u8; NUM_BYTES_IN_BLOCK as usize] = [0; NUM_BYTES_IN_BLOCK as usize];

    read_block_from_file(shared_file, block_id, &mut buffer);

    let mut hash_layers: Vec<u8> = buffer.to_vec();
    let mut root_hash: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];

    let mut number_id_fragment = position / HASH_BYTES_LEN as u32;
    let mut fragment_start_indx = (number_id_fragment) as usize*HASH_BYTES_LEN;//layer_len % HASH_BYTES_LEN;
    debug!("fragment_start_indx is {}", fragment_start_indx);

    let mut file2 = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .write(true)
        .open("hash-layers.txt")
        .unwrap();
    let mut i = 0;
    let mut counter = 0;
    while (i + HASH_BYTES_LEN < hash_layers.len()) {
        let mut first_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        first_fragment.copy_from_slice(&hash_layers[i..i + HASH_BYTES_LEN]);

        let mut second_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        second_fragment.copy_from_slice(&hash_layers[i + HASH_BYTES_LEN..i + HASH_BYTES_LEN * 2]);

        //QUA i DEVE ESSERE MINORE DI BUFFER.LEN/hash.....
        //o aspetta forse dovrebbe essere solo cosi'
        //if counter < buffer.len()/(HASH_BYTES_LEN*2) {
        //if counter < buffer.len()/HASH_BYTES_LEN {
        if i<buffer.len() {
            first_fragment = *blake3::hash(&first_fragment).as_bytes();
            second_fragment = *blake3::hash(&second_fragment).as_bytes();
            //counter += 1;
            //let mut ccstr = "*".to_string();
            for b in &first_fragment{
                let mut ccstr: String = b.to_string() + ", ";
                file2.write(ccstr.as_bytes());
            }
            file2.write("*\n".to_string().as_bytes());

            for b in &second_fragment{
                let mut ccstr = b.to_string() + ", ";
                file2.write(ccstr.as_bytes());
            }
            file2.write("*\n".to_string().as_bytes());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&first_fragment);
        hasher.update(&second_fragment);
        let new_hash = hasher.finalize();
        if i == fragment_start_indx as usize {
            debug!("Real first_fragment == {:?}\nReal second_fragment == {:?}\nNew_hash == {:?}",first_fragment,second_fragment,new_hash.as_bytes());
        }
        if i == fragment_start_indx as usize-HASH_BYTES_LEN {
            debug!("*Real first_fragment == {:?}\nReal second_fragment == {:?}\nNew_hash == {:?}",first_fragment,second_fragment,new_hash.as_bytes());
        }
        hash_layers.extend(new_hash.as_bytes());

        i = i + HASH_BYTES_LEN * 2;
    }
    file2.write("\nFINE".to_string().as_bytes());

    root_hash.copy_from_slice(&hash_layers[hash_layers.len()-HASH_BYTES_LEN..]);

    let mut counter = 0;
    let mut flag = false;
    let mut lay_len = buffer.len();
    debug!("Hash_layers == {:?}", hash_layers.len());
        for b in &hash_layers {
            let mut ccstr = b.to_string() + ", ";
            if counter%HASH_BYTES_LEN==0{
                ccstr = String::from("*\n") + &ccstr;
            }
            if counter==lay_len{
                ccstr = ccstr + "\n--> " + &lay_len.to_string() + "\n";
                flag = true;
            }
            // if counter%buffer.len()==0{
            //     ccstr = String::from("+") + &ccstr;
            // }
            if flag == true{
                file2.write(ccstr.as_bytes());
            }
            if counter == lay_len{
                counter = 0;
                lay_len = lay_len/2;
            }
            counter+=1;
        }
    debug!("root_hash == {:?}", root_hash);
    let mut i = 0;
    let mut layer_len = buffer.len();
    let mut siblings = Vec::new();
    //let fragment_num_in_layer = layer_len / HASH_BYTES_LEN;
    let mut layer_counter = buffer.len();
    let mut self_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
    let mut is_first_iter = true;
    debug!("position == {}", position);

    // let mut fragment_index = position % HASH_BYTES_LEN as u32;   not needed
    let mut count_frag = layer_len/HASH_BYTES_LEN;
    //while (layer_len > HASH_BYTES_LEN) {
    while (layer_len/HASH_BYTES_LEN > 1) {  //last layer before root
        debug!("layer_len == {}", layer_len);
        debug!("layer_counter == {}", layer_counter);
        debug!("number fragment == {} over {} fragments", number_id_fragment, layer_len/HASH_BYTES_LEN);
        debug!("count_frag == {}", count_frag);
        debug!("fragment_indx start == {}", fragment_start_indx);
        let mut sibling_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
//15158  23964
        let mut direction_sibling;
        if (number_id_fragment % 2 == 0) {
            direction_sibling = Direction::Right;
            sibling_fragment.copy_from_slice(
                &hash_layers[fragment_start_indx + HASH_BYTES_LEN..fragment_start_indx + HASH_BYTES_LEN * 2],
            );
        } else {
            direction_sibling = Direction::Left;
            sibling_fragment
                .copy_from_slice(&hash_layers[(fragment_start_indx - HASH_BYTES_LEN)..fragment_start_indx]);
        }
        
        //let hash_sibling = blake3::hash(&sibling_fragment);

        if is_first_iter {
            sibling_fragment = *blake3::hash(&sibling_fragment).as_bytes();
            //debug!("Sibling_fragment hash == {:?}",sibling_fragment);
        }
        // siblings.push(Sibling_Mod::new(hash_sibling, direction_sibling));
        siblings.push(Sibling_Mod::new(blake3::Hash::from_bytes(sibling_fragment), direction_sibling));

        if is_first_iter {
            is_first_iter = false;
            self_fragment
                .copy_from_slice(&hash_layers[fragment_start_indx..fragment_start_indx + HASH_BYTES_LEN]);
        }
        // layer_len = layer_len / 2;
        // // layer_counter += layer_len;
        // number_id_fragment = number_id_fragment/2;
        // // fragment_indx = layer_counter + layer_len % HASH_BYTES_LEN;   Sbagliato credo
        // fragment_start_indx = layer_counter + (number_id_fragment as usize)*HASH_BYTES_LEN;
        // fragment_start_indx = (count_frag-1)*HASH_BYTES_LEN;
        // layer_counter += layer_len;
        // count_frag += layer_len/HASH_BYTES_LEN;

        layer_len = layer_len / 2;
        // layer_counter += layer_len;
        number_id_fragment = number_id_fragment/2;
        // fragment_indx = layer_counter + layer_len % HASH_BYTES_LEN;   Sbagliato credo
        // fragment_start_indx = layer_counter + (number_id_fragment as usize)*HASH_BYTES_LEN;

        count_frag = layer_counter/HASH_BYTES_LEN + number_id_fragment as usize;

        layer_counter += layer_len;
        // count_frag += number_id_fragment as usize;//layer_len/HASH_BYTES_LEN;


        fragment_start_indx = (count_frag)*HASH_BYTES_LEN;

    }
    let self_fragment_hash = blake3::hash(&self_fragment);
    debug!("Self_fragment xxx == {:?}\nSelf_fragment hash == {:?}",self_fragment,self_fragment_hash);
    debug!("Siblings length == {:?}",siblings.len());

    return (Proof_Mod::new(siblings), self_fragment, root_hash);

//initialization: layer_len==500k, layer_counter==500k,
//      number_id_fragment==position / HASH_BYTES_LEN, 
//      fragment_start_indx==number_id_fragment*HASH_BYTES_LEN

//iter1(end of first iter): layer_len==250k, layer_counter==750k,
//      number_id_fragment==, 
//      fragment_start_indx==


//iter2: layer_len==, layer_counter==,
//      number_id_fragment==, 
//      fragment_start_indx==


    //             A               
    //         A       a     is index % 2 == 0 --> No then take sibling on the R
    //       a   A   a   a   is index % 2 == 0 --> No then take sibling on the L
    //      a a A a a a a a  is index % 2 == 0 --> Yes then take sibling on the R

    //                    A               
    //            A               a             is index % 2 == 0 --> No then take sibling on the R
    //        a       A       a       a         is index % 2 == 0 --> No then take sibling on the L
    //      a   a   A   a   a   a   a   a       is index % 2 == 0 --> Yes then take sibling on the R
    //     a a a a a A a a a a a a a a a a

    //                  Next level position di A is index = index / 2
    //                  At every new level, • Identify the reference position of A: the sibling is either on the left or on the right of A
    // a a A a a a a a  a A a a  A a  A
}



pub fn handle_stream<'a>(stream: &mut TcpStream, data: &'a mut [u8]) -> &'a [u8] {
    // let mut stream_opt_clone = stream_opt.clone();
    // let mut locked_stream = stream_opt_clone.lock().unwrap();//stream_opt.lock().unwrap().as_ref().clone();
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

pub fn create_and_send_proof_batches(
    stream: &Option<TcpStream>,
    mut seed: u8,
    _receiver: &Receiver<NotifyNode>,
    file: &Arc<Mutex<File>>,
    mut iteration: u32,
) -> (u8, u32) {
    let mut block_id: u32 = INITIAL_BLOCK_ID; // Given parameter
    let mut position: u32 = INITIAL_POSITION; // Given parameter
    let mut proof_batch: [u8; BATCH_SIZE] = [0; BATCH_SIZE];
    debug!("Preparing batch of proofs.");
    error!("SEED == {}", seed);
    let init_iteration = iteration;
    while (iteration < init_iteration + proof_batch.len() as u32) {
        (block_id, position, seed) = random_path_generator1(seed, iteration as u8);

        proof_batch[(iteration - init_iteration) as usize] =
            read_byte_from_file(file, block_id, position);
        warn!(
            "P: Iteration: {}, block_id = {}, position = {}, value = {}",
            iteration - init_iteration,
            block_id,
            position,
            proof_batch[(iteration - init_iteration) as usize]
        );

        iteration += 1;
    }

    let mut response_msg: [u8; BATCH_SIZE + 1] = [1; BATCH_SIZE + 1];
    //the tag is 1
    response_msg[1..].copy_from_slice(&proof_batch);
    debug!("Before send_msg_prover");
    send_msg(stream.as_ref().unwrap(), &response_msg);
    debug!("Batch of proofs sent from prover to verifier");
    return (seed, iteration);
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
    //debug!("block_id == {} while position == {}", block_id, position);
    //debug!("index == {} while file is long {}", index, metadata.unwrap().len());

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

pub fn read_block_from_file(
    shared_file: &Arc<Mutex<File>>,
    block_id: u32,
    buffer: &mut [u8],
) -> Vec<u8> {
    let mut file = shared_file.lock().unwrap();
    let index = (block_id * NUM_BYTES_IN_BLOCK) as u64;

    let metadata = file.metadata();
    //debug!("block_id == {} while position == {}", block_id, position);
    //debug!("index == {} while file is long {}", index, metadata.unwrap().len());

    file.seek(SeekFrom::Start(index)).unwrap();

    match file.read_exact(buffer) {
        Ok(_) => {}
        Err(e) => {
            error!("Error reading file == {:?}", e)
        }
    };

    return buffer.to_vec();
}
