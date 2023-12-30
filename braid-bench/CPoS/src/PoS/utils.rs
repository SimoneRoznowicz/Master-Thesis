use crate::Merkle_Tree::structs::{Direction, Proof, Proof_Mod, Sibling};
use log::debug;
use talk::crypto::primitives::hash::Hash;

// Helper function to convert the Proof struct into a vector of bytes
pub fn from_proof_to_bytes<'a>(proof: Proof_Mod, vec: &mut Vec<u8>) /*-> &'a Vec<u8>*/
{
    //[tag, direction, 32_hash_bytes..., direction, 32_hash_bytes,...]
    let tag = 4;
    vec.push(tag);
    for sibling in proof.get_siblings() {
        let bytes_hash = sibling.get_hash().as_bytes();
        let direction = sibling.get_direction();
        match *direction {
            Direction::Left => vec.push(0),  //Left  --> 0
            Direction::Right => vec.push(1), //Right --> 1
        }
        vec.extend_from_slice(bytes_hash);
    }
    debug!("from_proof_to_bytes: vec == {:?}", vec);
}

/// Helper function to convert a vector of into the Proof structs
pub fn from_bytes_to_proof(vec: Vec<u8>) -> Proof {
    //[direction, 32_hash_bytes..., direction, 32_hash_bytes,...]
    let mut siblings: Vec<Sibling> = Vec::new();
    let len_hash = 32;
    let mut i = 0;
    debug!("from_bytes_to_proof: vec == {:?}", vec);
    while i < vec.len() {
        let direction: Direction;
        if vec[i] == 0 {
            direction = Direction::Left;
        } else {
            direction = Direction::Right;
        }
        let mut hash_bytes: [u8; 32] = Default::default();
        hash_bytes.copy_from_slice(&vec[i + 1..i + 1 + len_hash]);
        debug!("from_bytes_to_proof: hash_bytes == {:?}", hash_bytes);
        let hash = Hash::from_bytes(hash_bytes);
        let sibling = Sibling::new(hash, direction);
        siblings.push(sibling);
        i += len_hash + 1;
    }
    return Proof::new(siblings);
}
