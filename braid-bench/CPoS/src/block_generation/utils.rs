pub mod Utils {
    pub static num_fragments_per_block: u32 = 1000;
    pub static num_block_per_unit: u32 = 100;
    pub const BATCH_SIZE: usize = 10;                 //Indicates the batch size of proofs that should be sent to the verifier at every 
    pub static MAX_NUM_PROOFS: usize = BATCH_SIZE*100;
    pub static initial_block_id: u32 = 0;
    pub static initial_position: u32 = 0;
}
