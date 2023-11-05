pub struct Node {
    id: u64,
    variant: NodeType, 
}

impl Node {
    pub fn new(id: u64, variant: NodeType) -> Node {
        Node {
            id,
            variant,
            // Initialize other variant-specific member variables here
        }
    }

    // Getter method for id
    pub fn get_id(&self) -> u64 {
        self.id
    }
}

pub enum NodeType {
    Prover,
    Verifier
}