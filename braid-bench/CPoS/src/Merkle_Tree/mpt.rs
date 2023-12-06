use crate::Merkle_Tree::util::*;
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

        let mut_node_err = match node_err {
            Ok(n) => {}
            Err(e) => return Proof::new(siblings),
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

/// Helper function to convert the Proof struct into a vector of bytes
pub fn from_proof_to_bytes(proof: Proof) -> Vec<u8>{  //[tag, direction, 32_hash_bytes..., direction, 32_hash_bytes,...]
    let mut vec: Vec<u8> = Vec::new();
    let tag = 4;
    vec.push(tag);
    for sibling in proof.get_siblings(){
        let bytes_hash = sibling.get_hash().to_bytes();
        let direction = sibling.get_direction();
        match *direction{
            Direction::Left => {vec.push(0)},       //Left  --> 0
            Direction::Right => {vec.push(1)},      //Right --> 1
        }
        vec.extend_from_slice(&bytes_hash);
    }
    return vec;
}

/// Helper function to convert a vector of into the Proof structs
pub fn from_bytes_to_proof(vec: Vec<u8>) -> Proof {  //[direction, 32_hash_bytes..., direction, 32_hash_bytes,...]
    let mut siblings: Vec<Sibling> = Vec::new();
    let len_hash = 32;
    let mut i = 0;
    while(i<vec.len()){
        let direction: Direction;
        if vec[i] == 0 {direction = Direction::Left;}
        else {direction = Direction::Right;}
        let mut hash_bytes: [u8; 32] = Default::default();
        hash_bytes.copy_from_slice(&vec[i + 1..i + 1 + len_hash]);
        let hash = Hash::from_bytes(hash_bytes);
        let sibling = Sibling::new(hash,direction);
        siblings.push(sibling);
        i += len_hash+1;
    }
    return Proof::new(siblings);
}

