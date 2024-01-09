pub mod Utils {
    use crate::block_generation::blockgen::GROUP_SIZE;

    /*A block_group is made of a Vec<[u64,4]>: a Vector containing (2^16 = 65536 elements).
      So in total: there are 2^18 = 262144 u64 elements --> 2^21 = 2097152 u8 elements in a block_group
      A single block is instead made of u8_in_a_block_group/4 = 2^19 = 524288 total bytes
    */
    // position in the block is u32 type

    pub const BUFFER_DATA_SIZE: usize = 10000;

    pub const NUM_BYTES_IN_BLOCK: u32 = 524288; // 2^19 bytes
    pub static NUM_BYTES_IN_BLOCK_GROUP: u32 = 2097152; // 2^21 bytes
    pub static NUM_FRAGMENTS_PER_UNIT: u32 = 1000;
    pub static NUM_BLOCK_GROUPS_PER_UNIT: u64 = 5;
    pub static NUM_BLOCKS_PER_UNIT: usize = NUM_BLOCK_GROUPS_PER_UNIT as usize * GROUP_SIZE;
    pub static MAX_NUM_PROOFS: usize = BATCH_SIZE * 100;
    pub static INITIAL_BLOCK_ID: u32 = 0;
    pub static INITIAL_POSITION: u32 = 0;
    pub static NUM_PROOFS_TO_VERIFY: u32 = 10;
    pub static VERIFIABLE_RATIO: f32 = 0.25;
    pub const NUM_BYTES_PER_BLOCK_ID: usize = 4;
    pub const NUM_BYTES_PER_POSITION: usize = 4;
    pub const HASH_BYTES_LEN: usize = 32;
    pub const FRAGMENT_SIZE: usize = 32;

    pub const BATCH_SIZE: usize = 50; //Indicates the batch size of proofs that should be sent to the verifier at every

    // Lowest accepted percentage of blocks not stored by the prover. If the verifier detects that the prover
    // didn't store at least LOWEST_ACCEPTED_STORING_PERCENTAGE of blocks, the timeout is exceeded and the challenge is not passed.
    pub const LOWEST_ACCEPTED_STORING_PERCENTAGE: f32 = 0.9;
}
