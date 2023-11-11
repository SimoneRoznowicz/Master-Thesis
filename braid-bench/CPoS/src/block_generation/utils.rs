pub mod Utils {
    pub static num_fragments_per_block: u32 = 1000;
    pub static num_block_per_unit: u32 = 100;
    pub static num_iterations: u32 = 7;     
    pub const BATCH_SIZE: usize = 10;                 //Indicates the batch size of proofs that should be sent to the verifier at every 
}
