use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{block_generation::utils::Utils::FRAGMENT_SIZE, Merkle_Tree::structs::*};
use log::info;

pub fn get_root_hash(
    proof: &Proof,
    key: (u32, u32),
    shared_map: &Arc<Mutex<HashMap<(u32, u32), u8>>>,
    mut self_fragment: [u8; FRAGMENT_SIZE],
) -> blake3::Hash {
    let block_id = key.0;
    let position = key.1;

    let siblings: &Vec<Sibling> = proof.get_siblings();

    info!(
        "Verifier: value == {:?} self_fragment == {:?}",
        shared_map
            .lock()
            .unwrap()
            .get(&(block_id.clone(), position.clone())),
        self_fragment
    );

    let mut hash_final = blake3::hash(&self_fragment);
    for sibling in siblings {
        let sibling_hash = sibling.get_hash().as_bytes();
        let curr_hash = hash_final.as_bytes();
        match sibling.get_direction() {
            Direction::Left => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(sibling.get_hash().as_bytes());
                hasher.update(hash_final.as_bytes());
                hash_final = hasher.finalize();
            }
            Direction::Right => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(hash_final.as_bytes());
                hasher.update(sibling.get_hash().as_bytes());
                hash_final = hasher.finalize();
            }
        }
    }
    hash_final
}
