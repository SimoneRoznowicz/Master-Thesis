use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Debug)]
pub struct Sibling {
    hash: blake3::Hash,
    direction: Direction,
}

impl Sibling {
    /// Returns a new Sibling.
    pub fn new(h: blake3::Hash, d: Direction) -> Sibling {
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
    pub fn get_hash(&self) -> &blake3::Hash {
        &self.hash
    }
}

#[derive(Debug)]
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
