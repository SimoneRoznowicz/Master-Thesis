
use crate::Merkle_Tree::{node_generic::*, structs::*};
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
