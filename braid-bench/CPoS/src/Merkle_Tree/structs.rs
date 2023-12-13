use serde::{Deserialize, Serialize};
use talk::crypto::primitives::hash::Hash;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Direction {
    Left,
    Right,
}

impl From<Left> for Direction {
    fn from(left: Left) -> Self {
        Direction::Left
    }
}

impl From<Right> for Direction {
    fn from(left: Right) -> Self {
        Direction::Right
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Left {}

impl Left {
    /// Returns the boolean associated with Left: false.
    fn get_val() -> bool {
        false
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Right {}

impl Right {
    /// Returns the boolean associated with Right: true.
    fn get_val() -> bool {
        true
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Id<K>
where
    K: Serialize,
{
    key: K,
}

impl<K> Id<K>
where
    K: Serialize,
{
    /// Returns a new Id.
    pub fn new(k: K) -> Self {
        Id { key: k }
    }

    /// Returns the key associated with the Id invoking the method.
    pub fn get_key(&self) -> &K {
        &self.key
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Sibling {
    hash: Hash,
    direction: Direction,
}

impl Sibling {
    /// Returns a new Sibling.
    pub fn new(h: Hash, d: Direction) -> Sibling {
        Sibling {
            hash: h,
            direction: d,
        }
    }

    /// Returns the direction associated with the Sibling invoking the method.
    pub fn get_direction(&self) -> &Direction {
        &self.direction
    }

    /// Returns the Hash associated with the Sibling invoking the method.
    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Proof {
    siblings: Vec<Sibling>,
}

impl Proof {
    /// Returns a new Proof.
    pub fn new(s: Vec<Sibling>) -> Proof {
        Proof { siblings: s }
    }

    /// Returns a reference to the vector of Siblings associated with the Proof invoking the method.
    pub fn get_siblings(&self) -> &Vec<Sibling> {
        &self.siblings
    }
}
