// pub fn handle_verification(msg: &[u8], stream: &TcpStream) -> bool {
//     return verify_time_challenge_bound() && verify_proofs(msg, stream); //if the first is wrong, don't execute verify_proofs
// }

// pub fn verify_time_challenge_bound() -> bool {
//     return true;
// }

// pub fn verify_proofs(msg: &[u8], stream: &TcpStream) -> bool {
//     let _proof_batch = msg[1..].to_vec();
//     // if NUM_PROOFS_TO_VERIFY > msg.len().try_into().unwrap() {
//     //     //NUM_PROOFS_TO_VERIFY = msg.len().try_into().unwrap() };
//     // }

//     let mut rng = rand::thread_rng();
//     let mut shuffled_elements: Vec<u8> = msg.to_vec();
//     shuffled_elements.shuffle(&mut rng);

//     for i in 0..NUM_PROOFS_TO_VERIFY {
//         if !sample_generate_verify(msg, stream, i) {
//             return false;
//         };
//     }
//     return true;
// }

// pub fn sample_generate_verify(msg: &[u8], _stream: &TcpStream, _i: u32) -> bool {
//     //first calculate the seed for each possible block: which means block_id and position. Store in a vector
//     let mut block_id: u32 = INITIAL_BLOCK_ID; // Given parameter
//     let mut position: u32 = INITIAL_POSITION; //Given parameter
//     let seed = msg[1];
//     let proof_batch: [u8; BATCH_SIZE] = [0; BATCH_SIZE];
//     let mut seed_sequence: Vec<(u32, u32)> = vec![];
//     for iteration_c in 0..proof_batch.len() {
//         (block_id, position) = random_path_generator(block_id, iteration_c, position, seed);
//         seed_sequence.push((block_id, position));
//     }

//     //generate_block(i);
//     //verify_proof(i);
//     return false;
// }

// pub fn random_path_generator(id: u32, c: usize, p: u32, s: u8) -> (u32, u32) {
//     let mut hasher_nxt_block = DefaultHasher::new();
//     let mut hasher_nxt_pos = DefaultHasher::new();

//     // let f =  str_to_u64(num_fragments_per_block);
//     s.hash(&mut hasher_nxt_block);
//     id.hash(&mut hasher_nxt_block);
//     c.hash(&mut hasher_nxt_block);
//     p.hash(&mut hasher_nxt_block);
//     let new_id = hasher_nxt_block.finish() % NUM_BLOCK_GROUPS_PER_UNIT as u64;

//     s.hash(&mut hasher_nxt_pos);
//     id.hash(&mut hasher_nxt_pos);
//     c.hash(&mut hasher_nxt_pos);
//     p.hash(&mut hasher_nxt_pos);
//     NUM_FRAGMENTS_PER_UNIT.hash(&mut hasher_nxt_pos);
//     let new_p = hasher_nxt_pos.finish() % NUM_FRAGMENTS_PER_UNIT as u64;

//     return (new_id.try_into().unwrap(), new_p.try_into().unwrap());
// }
