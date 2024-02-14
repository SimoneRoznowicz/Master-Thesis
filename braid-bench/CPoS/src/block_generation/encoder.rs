use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::io::{Read, SeekFrom};
use std::mem::transmute;
use std::time::Instant;

use aes::Aes128;
use blake3;
use log::debug;

use crate::block_generation::blockgen::{
    block_gen, InitGroup, GROUP_BYTE_SIZE, GROUP_SIZE, INIT_SIZE, N,
};
use crate::block_generation::utils::Utils::NUM_BLOCK_GROUPS_PER_UNIT;
use crate::PoS::prover::read_block_from_input_file;

use super::blockgen::BlockGroup;
use super::utils::Utils::{FRAGMENT_SIZE, HASH_BYTES_LEN, NUM_BYTES_IN_BLOCK_GROUP};
type Aes128Cbc = cbc::Encryptor<Aes128>;

const ID_PUBLIC_KEY: &[u8] = b"727 is a funny number";

pub fn generate_commitment_hash(input_file: &mut File, block_id: u32) -> [u8; 32] {
    let mut buffer = vec![0; NUM_BYTES_IN_BLOCK_GROUP as usize];
    read_block_from_input_file(input_file, block_id, &mut buffer);

    let mut hash_layers: Vec<u8> = buffer.to_vec();
    let mut root_hash: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];

    let mut i = 0;
    while i + HASH_BYTES_LEN < hash_layers.len() {
        let mut first_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        first_fragment.copy_from_slice(&hash_layers[i..i + HASH_BYTES_LEN]);

        let mut second_fragment: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
        second_fragment.copy_from_slice(&hash_layers[i + HASH_BYTES_LEN..i + HASH_BYTES_LEN * 2]);

        if i < buffer.len() {
            first_fragment = *blake3::hash(&first_fragment).as_bytes();
            second_fragment = *blake3::hash(&second_fragment).as_bytes();
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&first_fragment);
        hasher.update(&second_fragment);
        let new_hash = hasher.finalize();

        hash_layers.extend(new_hash.as_bytes());

        i = i + HASH_BYTES_LEN * 2;
    }
    root_hash.copy_from_slice(&hash_layers[hash_layers.len() - HASH_BYTES_LEN..]);

    return root_hash;
}

pub fn encode(
    mut input_file: File,
    mut output_file: &File,
    mut root_hashes: &mut Vec<[u8; HASH_BYTES_LEN]>,
) -> io::Result<()> {
    let startup = Instant::now();

    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    // Compute input and output file sizes
    let input_lenght = input_file.seek(SeekFrom::End(0))?;
    input_file.seek(SeekFrom::Start(0))?;
    let block_count = ((input_lenght - 1) / GROUP_BYTE_SIZE as u64) + 1;
    unsafe { NUM_BLOCK_GROUPS_PER_UNIT = block_count };
    let output_lenght = 8 + (64 * block_count) + block_count * GROUP_BYTE_SIZE as u64;
    output_file.set_len(output_lenght)?;

    // Write input file size at the start of output file
    let size_bytes: [u8; 8] = unsafe { transmute(input_lenght.to_le()) };
    output_file.write_all(&size_bytes)?;
    let mut cc = 0;

    for i in 0..block_count {
        root_hashes.push(generate_commitment_hash(&mut input_file, i as u32));
    }
    debug!(
        "Length of generated root hashes vector == {:?}",
        root_hashes.len()
    );

    input_file.seek(SeekFrom::Start(0))?;

    // Write blocks
    for i in 0..block_count {
        let mut input = vec![0u8; GROUP_BYTE_SIZE];
        input_file.read(&mut input)?;

        // Compute init vectors
        let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
        for g in 0..GROUP_SIZE {
            let pos_bytes: [u8; 8] =
                unsafe { transmute(((i * GROUP_SIZE as u64) + g as u64).to_le()) };
            let mut hasher = blake3::Hasher::new();
            hasher.update(&pos_bytes);
            hasher.update(pub_hash.as_bytes());
            hasher.update(&root_hashes[i as usize]);

            let block_hash = hasher.finalize();
            let block_hash = block_hash.as_bytes();
            for i in 0..INIT_SIZE {
                let mut hash_bytes = [0u8; 8];
                for j in 0..8 {
                    hash_bytes[j] = block_hash[i * 8 + j]
                }
                inits[i][g] = u64::from_le_bytes(hash_bytes);
            }
        }

        let mut start_t = Instant::now();
        // Compute block_gen
        let group = block_gen(inits);

        let mut end_t = Instant::now();
        debug!("Time to Create a block: {}", (end_t - start_t).as_micros());

        // Compute input hash
        let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
        let input_hash = root_hashes[i as usize];

        for i in 0..32 {
            output.push(input_hash[i]);
        }

        // Compute the output : XOR the input with the output of f
        for i in 0..(N * GROUP_SIZE) {
            let mut data_bytes = [0u8; 8];
            for j in 0..8 {
                data_bytes[j] = input[i * 8 + j];
            }
            let mut data = u64::from_le_bytes(data_bytes);
            data = data ^ group[i / GROUP_SIZE][i % GROUP_SIZE];
            data_bytes = unsafe { transmute(data.to_le()) };
            for j in 0..8 {
                output.push(data_bytes[j]);
            }
        }

        // Write to file
        output_file.write_all(&output)?;
    }

    let ttotal = startup.elapsed();
    let ms = ttotal.as_micros() as f32 / 1_000.0;
    println!("Encoded the file in {}ms", ms);
    Ok(())
}

pub fn generate_xored_data(
    block_id: u32,
    position: u32,
    root_hash: [u8; HASH_BYTES_LEN],
    self_fragment: [u8; FRAGMENT_SIZE],
    flag: bool,
) -> Vec<u8> {
    // Compute input hash
    let group = generate_PoS(block_id as u64, root_hash);
    let mut input = vec![0u8; GROUP_BYTE_SIZE];
    debug!("position =={}", position);
    let mut number_id_fragment = position / HASH_BYTES_LEN as u32;
    let mut indx_start = (number_id_fragment) as usize * HASH_BYTES_LEN; //layer_len % HASH_BYTES_LEN;

    // let indx_start = position / FRAGMENT_SIZE as u32;
    let indx_end = indx_start + FRAGMENT_SIZE;

    let mut k = 0;
    for i in indx_start..indx_end {
        input[i as usize] = self_fragment[k];
        k += 1;
    }

    debug!("indx_start == {:?}, indx_end == {}", indx_start, indx_end);

    debug!("self_fragment == {:?}", self_fragment);
    let part_input = &input[indx_start as usize..indx_end as usize + 5];
    debug!("Input == {:?}", part_input);

    let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
    let input_hash = root_hash;

    for i in 0..32 {
        output.push(input_hash[i]);
    }

    // Compute the output : XOR the input with the output of f
    let mut flag = false;
    let margin = (position as u32 / 8 as u32) as usize;
    for i in 0..(N * GROUP_SIZE) {
        let mut data_bytes = [0u8; 8];
        for j in 0..8 {
            data_bytes[j] = input[i * 8 + j];
        }
        let mut data = u64::from_le_bytes(data_bytes);
        if data != 0 {
            flag = true;
            debug!(
                "\n V Index i*8 =={} data_bytes =={:?},\n data u64 == {}",
                i * 8,
                data_bytes,
                data
            );
        }

        data = data ^ group[i / GROUP_SIZE][i % GROUP_SIZE];
        data_bytes = unsafe { transmute(data.to_le()) };

        for j in 0..8 {
            output.push(data_bytes[j]);
        }
        flag = false;
    }
    return output[HASH_BYTES_LEN + indx_start as usize..HASH_BYTES_LEN + indx_end as usize]
        .to_vec();
}

pub fn generate_PoS(block_id: u64, root_hash: [u8; HASH_BYTES_LEN]) -> BlockGroup {
    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    // Compute init vectors
    let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
    for g in 0..GROUP_SIZE {
        let pos_bytes: [u8; 8] =
            unsafe { transmute(((block_id * GROUP_SIZE as u64) + g as u64).to_le()) };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pos_bytes);
        hasher.update(pub_hash.as_bytes());
        hasher.update(&root_hash);

        let block_hash = hasher.finalize();
        let block_hash = block_hash.as_bytes();
        for i in 0..INIT_SIZE {
            let mut hash_bytes = [0u8; 8];
            for j in 0..8 {
                hash_bytes[j] = block_hash[i * 8 + j]
            }
            inits[i][g] = u64::from_le_bytes(hash_bytes);
        }
    }

    // Compute block_gen
    let group = block_gen(inits);
    return group;
}
