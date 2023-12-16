use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use serde_json::error;
use log::{debug, error, info, trace, warn};

use crate::block_generation::utils::Utils::{
    NUM_BLOCK_GROUPS_PER_UNIT,
    NUM_FRAGMENTS_PER_UNIT, NUM_BLOCKS_PER_UNIT, NUM_BYTES_IN_BLOCK,
};


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
pub fn random_path_generator(seed: u8, iteration: u8) -> (u32, u32, u8) {
    let mut hasher_nxt_block = DefaultHasher::new();
    let mut hasher_nxt_pos = DefaultHasher::new();
    let mut hasher_seed = DefaultHasher::new();

    seed.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % NUM_BLOCKS_PER_UNIT as u64;
    info!("PROVER: hasher_nxt_block.finish()  {}", hasher_nxt_block.finish());

    seed.hash(&mut hasher_nxt_pos);
    NUM_BYTES_IN_BLOCK.hash(&mut hasher_nxt_pos);
    let new_p = hasher_nxt_pos.finish() % NUM_BYTES_IN_BLOCK as u64;      

    new_id.hash(&mut hasher_seed);
    new_p.hash(&mut hasher_seed);
    iteration.hash(&mut hasher_seed);
    let new_seed = hasher_seed.finish() % u8::MAX as u64;

    error!("VERIFIER: new_id == {}",new_id);
    error!("VERIFIER: new_p == {}",new_p);
    error!("VERIFIER: iteration == {}",iteration);
    error!("VERIFIER: new_seed inside == {}",new_seed);
    return (new_id.try_into().unwrap(), new_p.try_into().unwrap(), new_seed.try_into().unwrap());
}






pub fn random_path_generator1(seed: u8, iteration: u8) -> (u32, u32, u8) {
    let mut hasher_nxt_block = DefaultHasher::new();
    let mut hasher_nxt_pos = DefaultHasher::new();
    let mut hasher_seed = DefaultHasher::new();

    seed.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % NUM_BLOCKS_PER_UNIT as u64;
    info!("PROVER: hasher_nxt_block.finish()  {}", hasher_nxt_block.finish());

    seed.hash(&mut hasher_nxt_pos);
    NUM_BYTES_IN_BLOCK.hash(&mut hasher_nxt_pos);
    let new_p = hasher_nxt_pos.finish() % NUM_BYTES_IN_BLOCK as u64;      

    new_id.hash(&mut hasher_seed);
    new_p.hash(&mut hasher_seed);
    iteration.hash(&mut hasher_seed);
    let new_seed = hasher_seed.finish() % u8::MAX as u64;

    error!("PROVER: new_id == {}",new_id);
    error!("PROVER: new_p == {}",new_p);
    error!("PROVER: iteration == {}",iteration);
    error!("PROVER: new_seed inside == {}",new_seed);
    return (new_id.try_into().unwrap(), new_p.try_into().unwrap(), new_seed.try_into().unwrap());
}
    //P: 14 185 new_p=119881 new_id == 
    
// pub fn stop_sending_proofs(sender: mpsc::Sender<Signal>) { 
//     sender.send(Signal::Stop).unwrap();
// }
