use log::{debug, info};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::block_generation::utils::Utils::{NUM_BYTES_IN_BLOCK, NUM_BYTES_IN_BLOCK_GROUP, NUM_BLOCK_GROUPS_PER_UNIT};

// // Try not to generate every time
pub fn random_path_generator(seed: u8, iteration: u64) -> (u32, u32, u8) {
    let mut hasher_nxt_block = DefaultHasher::new();
    let mut hasher_nxt_pos = DefaultHasher::new();
    let mut hasher_seed = DefaultHasher::new();

    seed.hash(&mut hasher_nxt_block);
    let new_id = hasher_nxt_block.finish() % unsafe { NUM_BLOCK_GROUPS_PER_UNIT } as u64;  //NUM_BLOCKS_PER_UNIT NON HA PIU MOTIVO DI ESISTERE
    // info!(
    //     "PROVER: hasher_nxt_block.finish()  {}",
    //     hasher_nxt_block.finish()
    // );

    seed.hash(&mut hasher_nxt_pos);
    NUM_BYTES_IN_BLOCK.hash(&mut hasher_nxt_pos);
    let new_p = hasher_nxt_pos.finish() % NUM_BYTES_IN_BLOCK_GROUP as u64;

    new_id.hash(&mut hasher_seed);
    new_p.hash(&mut hasher_seed);
    iteration.hash(&mut hasher_seed);
    let new_seed = hasher_seed.finish() % u8::MAX as u64;

    debug!("VERIFIER: new_id == {}", new_id);
    debug!("VERIFIER: new_p == {}", new_p);
    debug!("VERIFIER: iteration == {}", iteration);
    info!("VERIFIER: new_seed inside == {}", new_seed);
    return (
        new_id.try_into().unwrap(),
        new_p.try_into().unwrap(),
        new_seed.try_into().unwrap(),
    );
}
