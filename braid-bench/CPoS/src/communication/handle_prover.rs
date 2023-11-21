use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::TcpStream;
use std::sync::mpsc;

use log::{info,warn,error};

use crate::block_generation::blockgen::SIZE;
use crate::block_generation::utils;
use crate::block_generation::utils::Utils::{BATCH_SIZE,NUM_BLOCK_PER_UNIT,NUM_FRAGMENTS_PER_UNIT,MAX_NUM_PROOFS,INITIAL_BLOCK_ID,INITIAL_POSITION};
use crate::communication::structs::Notification;





// pub fn handle_challenge(msg: &[u8], stream: &TcpStream, receiver: mpsc::Receiver<Signal>) {
//     let mut counter = 0;
//     while counter<MAX_NUM_PROOFS {
//         match receiver.try_recv() {  //PROBLEMA: QUA SI FERMA SEMPRE. MI SERVIREBBE UNA NOTIFICA CONTINUE A OGNI CICLO. INVECE IO VORREI UNA NOTIFICA STOP QUANDO SERVE E NEL RESTO DEL TEMPO RIMANE CONTINUE
//             Ok(notification) => {
//                 match notification {
//                     Signal::Continue => {
//                         create_and_send_proof_batches(msg,stream,&receiver);
//                     }
//                     Signal::Stop => {
//                         info!("Received Stop signal: the prover stopped sending proof batches");
//                         break;
//                     }
//                 }
//             }
//             Err(mpsc::TryRecvError::Empty) => {
//                 create_and_send_proof_batches(msg,stream,&receiver);
//             }
//             Err(mpsc::TryRecvError::Disconnected) => {
//                 error!("The prover has been disconnected");
//                 break;
//             }
//         }
//         counter += BATCH_SIZE;
//     }
// }

// pub fn create_and_send_proof_batches(msg: &[u8], stream: &TcpStream, receiver: &mpsc::Receiver<Signal>) {
//     let mut block_id: u32 = INITIAL_BLOCK_ID;  // Given parameter
//     let mut position: u32 = INITIAL_POSITION;  //Given parameter
//     let seed = msg[1];
//     let proof_batch: [u8;BATCH_SIZE] = [0;BATCH_SIZE];
//     for mut iteration_c in 0..proof_batch.len() {
//         (block_id, position) = random_path_generator(block_id, iteration_c, position, seed);
//         //proof_buffer[iteration_c] = 
//     }
//     let peer_addr = stream.peer_addr().unwrap().to_string(); 
//     info!("Preparing batch of proofs...");
//     let mut response_msg: [u8; BATCH_SIZE] = [1; BATCH_SIZE];
//     response_msg[1..].copy_from_slice(&proof_batch);
//     let my_slice: &[u8] = &response_msg;
    
//     start_client(&peer_addr, &response_msg);
//     info!("Batch of proofs sent to the verifier");
// }

// // Try not to generate every time
pub fn random_path_generator(id: u32, c: usize, p: u32, s: u8) -> (u32,u32) {
    let mut hasher_nxt_block = DefaultHasher::new();
    let mut hasher_nxt_pos = DefaultHasher::new();

    // let f =  str_to_u64(num_fragments_per_block);
    s.hash(&mut hasher_nxt_block);
    id.hash(&mut hasher_nxt_block);
    c.hash(&mut hasher_nxt_block);
    p.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % NUM_BLOCK_PER_UNIT as u64;

    s.hash(&mut hasher_nxt_pos);
    id.hash(&mut hasher_nxt_pos);
    c.hash(&mut hasher_nxt_pos);
    p.hash(&mut hasher_nxt_pos);
    NUM_FRAGMENTS_PER_UNIT.hash(&mut hasher_nxt_pos);
    let new_p = hasher_nxt_pos.finish() % NUM_FRAGMENTS_PER_UNIT as u64;

    return (new_id.try_into().unwrap(), new_p.try_into().unwrap());
}

// pub fn stop_sending_proofs(sender: mpsc::Sender<Signal>) {
//     sender.send(Signal::Stop).unwrap();
// }