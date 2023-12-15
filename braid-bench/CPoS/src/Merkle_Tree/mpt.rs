use crate::Merkle_Tree::node_generic::*;
use crate::Merkle_Tree::structs::*;

use serde::{Deserialize, Serialize};
use talk::crypto::primitives::hash::Hash;

/**
 * In this representation of the Merkle Patricia Tree,
 * • true <--> 1 <--> Right
 * • false <--> 0 <--> Left
**/

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, Hash)]
pub struct MerkleTree<K, V>
where
    K: Serialize,
    V: Serialize,
{
    root: Box<NodeGeneric<K, V>>,
}

impl<K, V> MerkleTree<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    /// Returns a new MerkleTree
    pub fn new() -> MerkleTree<K, V> {
        let n = Box::new(NodeGeneric::new_internal_default());
        MerkleTree { root: n }
    }

    /// Returns the root of the MerkleTree as a NodeGeneric.
    pub fn get_root(&self) -> &NodeGeneric<K, V> {
        &self.root
    }

    /// Returns the mutable root of the MerkleTree as NodeGeneric.
    pub fn get_mut_root(&mut self) -> &mut NodeGeneric<K, V> {
        &mut self.root
    }

    /// Returns the created Leaf node as NodeGeneric.
    /// Returns an already existing Leaf as NodeGeneric if the key to be inserted
    /// already exists. Inserts a new Leaf in the MerkleTree if the key is not
    /// contained or substitutes the current value associated to the given key.
    /// Panics if there is a collision
    pub fn insert(&mut self, key_to_add: K, value_to_add: V) -> NodeGeneric<K, V> {
        self.root.insert(key_to_add, value_to_add, 0)
    }

    /// Returns a Result which contains: a reference of the NodeGeneric associated
    /// to the given key, if the key is contained; Err(()) otherwise.
    /// Panics if the given key is not associated to any value in the MerkleTree.
    pub fn get_node(&self, key: K) -> Result<&NodeGeneric<K, V>, ()> {
        self.root.find_path(&key, 0)
    }

    /// Returns a reference of the value associated to the given key.
    /// Panics if the given key is not associated to any value in the MerkleTree.
    pub fn get_value(&self, key: K) -> &V {
        match self.get_node(key).unwrap() {
            NodeGeneric::Leaf(n) => n.get_value(),
            _ => panic!(),
        }
    }
}

impl<K, V> MerkleTree<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    /// Returns a Proof for the specific given key.
    /// The Proof contains an empty vector of Siblings if the key is not contained.
    pub fn prove(&mut self, key: K) -> Proof {
        let mut siblings = Vec::<Sibling>::new();
        let node_err = self.get_node(key.clone());

        let _mut_node_err = match node_err {
            Ok(_n) => {}
            Err(_e) => return Proof::new(siblings),
        };

        self.root.get_siblings(&key, 0, &mut siblings);
        siblings.reverse();
        Proof::new(siblings)
    }

    /// Returns the hash of the root of the MerkleTree. Recursively computes
    /// and assigns the corresponding Hash to every internal node.
    pub fn compute_hashes(&mut self) -> Hash {
        self.root.compute_hashes()
    }

    /// Returns a Proof for the specific given key.
    /// Sequentially invokes the methods:
    /// compute_hashes(&mut self) -> Hash  and
    /// prove(&mut self, key: K) -> Proof  
    /// The Proof contains an empty vector of Siblings if the key is not contained.
    pub fn compute_hashes_prove(&mut self, key: K) -> Proof {
        self.compute_hashes();
        self.prove(key)
    }
}
