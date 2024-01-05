use crate::{Merkle_Tree::{node_generic::*, structs::*}, block_generation::utils::Utils::{HASH_BYTES_LEN, FRAGMENT_SIZE}};
use log::{info, debug};
use serde::Serialize;
use talk::crypto::primitives::hash::{hash, Hash};

/// Returns the Hash of the root, computed according to the given proof.
pub fn get_root_hash<T, K>(proof: Proof, my_transactions: T, id: Id<K>) -> Hash
where
    T: Serialize + Clone,
    K: Serialize + Eq + Clone,
{
    let siblings = proof.get_siblings();
    let my_leaf = Leaf::<K, T>::new(id.get_key().clone(), my_transactions);

    let mut hash_final = my_leaf.get_hash();

    for sibling in siblings {
        match sibling.get_direction() {
            Direction::Left => hash_final = hash(&(sibling.get_hash(), hash_final)).unwrap(),
            Direction::Right => hash_final = hash(&(hash_final, sibling.get_hash())).unwrap(),
        }
    }
    hash_final
}

pub fn get_root_hash_mod(proof: &Proof_Mod, key: (u32, u32), value: u8, mut self_fragment: [u8;FRAGMENT_SIZE]) -> blake3::Hash
{
    let position = key.1;
    let indx_byte_in_self_fragment = position % FRAGMENT_SIZE as u32;
    let siblings: &Vec<Sibling_Mod> = proof.get_siblings();
    // let my_leaf = Leaf::<K, T>::new(id.get_key().clone(), my_transactions);

    //self_fragment[indx_byte_in_self_fragment as usize] = value;
    info!("Verifier: self_fragment == {:?}", self_fragment);
    let mut hash_final = blake3::hash(&self_fragment);
    debug!("HASH self fragment == {:?}",hash_final.as_bytes());
    for sibling in siblings {
        // let mut sibling_hash = sibling.get_hash().as_bytes();
        // let mut curr_hash;
        // curr_hash = hash_final.as_bytes();
        // debug!("HASH FINAL == {:?}",hash_final.as_bytes());
        // debug!("Sibling.get_hash() == {:?}", sibling.get_hash().as_bytes());
        match sibling.get_direction() {
            Direction::Left => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(sibling.get_hash().as_bytes());
                debug!("Left: Sibling hash == {:?}",sibling.get_hash().as_bytes());
                hasher.update(hash_final.as_bytes());
                debug!("Left: curr_hash == {:?}",hash_final.as_bytes());
                hash_final = hasher.finalize();
                debug!("Left: hash_final == {:?}",hash_final.as_bytes());
            },
            Direction::Right => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(hash_final.as_bytes());
                debug!("Right: curr_hash == {:?}",hash_final.as_bytes());
                hasher.update(sibling.get_hash().as_bytes());
                debug!("Right: Sibling hash == {:?}",sibling.get_hash().as_bytes());
                hash_final = hasher.finalize();
                debug!("Right: hash_final == {:?}",hash_final.as_bytes());
            },
        }
    }
    hash_final
}
