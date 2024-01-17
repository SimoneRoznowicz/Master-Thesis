use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    block_generation::utils::Utils::FRAGMENT_SIZE,
    Merkle_Tree::structs::*,
};
use log::{debug, error, info, warn};
use talk::crypto::primitives::hash::{hash, Hash};

pub fn get_root_hash(
    proof: &Proof,
    key: (u32, u32),
    shared_map: &Arc<Mutex<HashMap<(u32, u32), u8>>>,
    mut self_fragment: [u8; FRAGMENT_SIZE],
) -> blake3::Hash {
    let block_id = key.0;
    let position = key.1;

    let indx_byte_in_self_fragment = position % FRAGMENT_SIZE as u32;
    let siblings: &Vec<Sibling> = proof.get_siblings();

    // {
    //     let map = shared_map.lock().unwrap();
    //     match map.get(&(block_id.clone(), position.clone()))
    //     {
    //         Some(value) => {
    //             self_fragment[indx_byte_in_self_fragment as usize] = *value;
    //             warn!("Check this inclusion proof with my innput value. block_id == {}, position {}, value {}, \nMap == {:?}", block_id, position, *value, map);

    //         }
    //         None => {
    //             error!("Do not check this inclusion proof with my innput value. block_id == {} and position {} Map == {:?}", block_id, position, map);
    //         }
    //     };
    // }

    info!("Verifier: self_fragment == {:?}", self_fragment);
    let mut hash_final = blake3::hash(&self_fragment);
    //debug!("HASH self fragment == {:?}", hash_final.as_bytes());
    for sibling in siblings {
        let sibling_hash = sibling.get_hash().as_bytes();
        let curr_hash = hash_final.as_bytes();
        // debug!("HASH FINAL == {:?}",hash_final.as_bytes());
        // debug!("Sibling.get_hash() == {:?}", sibling.get_hash().as_bytes());
        match sibling.get_direction() {
            Direction::Left => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(sibling.get_hash().as_bytes());
                //debug!("Left: Sibling hash == {:?}", sibling.get_hash().as_bytes());
                hasher.update(hash_final.as_bytes());
                //debug!("Left: curr_hash == {:?}", hash_final.as_bytes());
                hash_final = hasher.finalize();
                //debug!("Left: hash_final == {:?}", hash_final.as_bytes());
            }
            Direction::Right => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(hash_final.as_bytes());
                //debug!("Right: curr_hash == {:?}", hash_final.as_bytes());
                hasher.update(sibling.get_hash().as_bytes());
                //debug!("Right: Sibling hash == {:?}", sibling.get_hash().as_bytes());
                hash_final = hasher.finalize();
                //debug!("Right: hash_final == {:?}", hash_final.as_bytes());
            }
        }
    }
    hash_final
}
