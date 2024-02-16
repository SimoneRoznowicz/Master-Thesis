pub mod Utils {

    /*A block_group is made of a Vec<[u64,4]>: a Vector containing (2^16 = 65536 elements).
      So in total: there are 2^18 = 262144 u64 elements --> 2^21 = 2097152 u8 elements in a block_group
      A single block is instead made of u8_in_a_block_group/4 = 2^19 = 524288 total bytes
    */
    // position and block id in the block are u32 type

    pub const BUFFER_DATA_SIZE: usize = 50000000;

    pub const NUM_BYTES_IN_BLOCK: u32 = 524288; // 2^19 bytes
    pub const NUM_BYTES_IN_BLOCK_GROUP: u32 = 2097152; // 2^21 bytes
    pub static mut NUM_BLOCK_GROUPS_PER_UNIT: u64 = 0;
    pub static INITIAL_BLOCK_ID: u32 = 0;
    pub static INITIAL_POSITION: u32 = 0;
    pub static VERIFIABLE_RATIO: f32 = 0.01;
    pub const NUM_BYTES_PER_BLOCK_ID: usize = 4;
    pub const NUM_BYTES_PER_POSITION: usize = 4;
    pub const HASH_BYTES_LEN: usize = 32;
    pub const FRAGMENT_SIZE: usize = 32;

    pub const BATCH_SIZE: usize = 70; //Indicates the batch size of proofs that should be sent to the verifier at every

    // Lowest accepted percentage of blocks not stored by the prover. If the verifier detects that the prover
    // didn't store at least LOWEST_ACCEPTED_STORING_PERCENTAGE of blocks, the timeout is exceeded and the challenge is not passed.
    pub const LOWEST_ACCEPTED_STORING_PERCENTAGE: f64 = 0.9;

    pub const TIME_LIMIT: u128 = 2 * 1000000; //2 seconds

    pub const GOOD_PROOF_AVG_TIMING: u128 = 50; //on this laptop
    pub const BAD_PROOF_AVG_TIMING: u128 = 11000; //on this laptop
}