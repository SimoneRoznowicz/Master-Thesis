pub struct Node {
    id: u64,
    variant: NodeType, 
}

impl Node {
    pub fn new(id: u64, variant: NodeType) -> Node {
        Node {id,variant}
    }
}

pub enum NodeType {
    Prover,
    Verifier
}