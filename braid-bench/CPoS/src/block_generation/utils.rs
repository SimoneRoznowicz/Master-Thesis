pub mod Utils {
    use std::ffi::c_float;
    // position in the block is u32 type
    pub static NUM_FRAGMENTS_PER_UNIT: u32 = 1000;
    pub static NUM_BLOCK_GROUPS_PER_UNIT: u64 = 5;
    pub const BATCH_SIZE: usize = 10; //Indicates the batch size of proofs that should be sent to the verifier at every
    pub static MAX_NUM_PROOFS: usize = BATCH_SIZE * 100;
    pub static INITIAL_BLOCK_ID: u32 = 0;
    pub static INITIAL_POSITION: u32 = 0;
    pub static NUM_PROOFS_TO_VERIFY: u32 = 10;
    pub static CHECKING_FACTOR: f32 = 0.25;
    pub const NUM_BYTES_PER_BLOCK_ID: usize = 4;
    pub const NUM_BYTES_PER_POSITION: usize = 4;
    pub const HASH_BYTES_LEN: usize = 32;
}
