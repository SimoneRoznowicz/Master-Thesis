use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::TcpStream;
use std::sync::mpsc;

use crate::block_generation::blockgen::SIZE;
use crate::block_generation::utils;
use crate::PoS::structs::NodeType;
use super::client::{start_client, self};
use crate::block_generation::utils::Utils::{BATCH_SIZE,num_block_per_unit,num_fragments_per_block,num_iterations,MAX_NUM_PROOFS};
use crate::communication::structs::Notification;


pub fn handle_challenge(msg: &[u8], stream: &TcpStream, receiver: mpsc::Receiver<Notification>) {
    let mut block_id: u32 = 1;  // Given parameter
    let mut init_position: u32 = 1;  //Given parameter
    let mut counter = 0;
    while counter<MAX_NUM_PROOFS {
        match receiver.try_recv() {  //PROBLEMA: QUA SI FERMA SEMPRE. MI SERVIREBBE UNA NOTIFICA CONTINUE A OGNI CICLO. INVECE IO VORREI UNA NOTIFICA STOP QUANDO SERVE E NEL RESTO DEL TEMPO RIMANE CONTINUE
            Ok(notification) => {
                match notification {
                    Notification::Continue => {
                        let seed = msg[1];
                        let proof_batch: [u8;BATCH_SIZE] = [0;BATCH_SIZE];
                        for mut iteration_c in 0..proof_batch.len() {
                            (block_id, init_position) = random_path_generator(block_id, iteration_c, init_position, seed);
                            //proof_buffer[iteration_c] = 
                        }
                        let peer_addr = stream.peer_addr().unwrap().to_string(); 
                
                        let mut response_msg: [u8; BATCH_SIZE] = [1; BATCH_SIZE];
                        response_msg[1..].copy_from_slice(&proof_batch);
                        let my_slice: &[u8] = &response_msg;
                        
                        start_client(&peer_addr, &response_msg);
                    }
                    Notification::Stop => {
                        break;
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => {

            }
            Err(mpsc::TryRecvError::Disconnected) => {
                // The sender has been disconnected, exit the loop
                break;
            }
            Err(_) => {
                // The sender has been disconnected, exit the loop
                break;
            }
        }
    }
}

// Try not to generate every time
pub fn random_path_generator(id: u32, c: usize, p: u32, s: u8) -> (u32,u32) {

    let mut hasher_nxt_block = DefaultHasher::new();
    let mut hasher_nxt_pos = DefaultHasher::new();

    // let f =  str_to_u64(num_fragments_per_block);
    s.hash(&mut hasher_nxt_block);
    id.hash(&mut hasher_nxt_block);
    c.hash(&mut hasher_nxt_block);
    p.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % num_block_per_unit as u64;

    s.hash(&mut hasher_nxt_pos);
    id.hash(&mut hasher_nxt_pos);
    c.hash(&mut hasher_nxt_pos);
    p.hash(&mut hasher_nxt_pos);
    num_fragments_per_block.hash(&mut hasher_nxt_pos);
    let new_p = hasher_nxt_pos.finish() % num_fragments_per_block as u64;

    return (new_id.try_into().unwrap(), new_p.try_into().unwrap());
}

pub fn stop_sending_proofs(sender: mpsc::Sender<Notification>) {
    sender.send(Notification::Stop).unwrap();
}