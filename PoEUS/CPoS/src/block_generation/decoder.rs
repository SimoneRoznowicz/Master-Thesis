use std::fs::File;
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

use super::encoder::generate_PoS;
use super::utils::Utils::HASH_BYTES_LEN;

type Aes128Cbc = cbc::Decryptor<Aes128>;

const ID_PUBLIC_KEY: &[u8] = b"727 is a funny number";

pub fn decode(
    mut input_file: &File,
    mut output_file: &File,
    root_hashes: &Vec<[u8; 32]>,
) -> io::Result<()> {
    let startup = Instant::now();

    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    // Compute/check input and output file sizes
    let input_lenght = input_file.seek(SeekFrom::End(0))?;
    input_file.seek(SeekFrom::Start(0))?;
    let mut size_bytes = [0u8; 8];
    input_file.read(&mut size_bytes)?;
    let output_lenght = u64::from_le_bytes(size_bytes);
    let block_count = ((output_lenght - 1) / GROUP_BYTE_SIZE as u64) + 1;
    assert!(input_lenght == 8 + (64 * block_count) + block_count * GROUP_BYTE_SIZE as u64);

    output_file.set_len(output_lenght)?;

    // Write blocks
    for i in 0..block_count {
        let mut input = vec![0u8; 32 + GROUP_BYTE_SIZE];
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

        // Compute block_gen
        let group = block_gen(inits);

        let mut output: Vec<u8> = Vec::with_capacity(GROUP_BYTE_SIZE);
        // Compute the output : XOR the input with the output of f
        for i in 0..(N * GROUP_SIZE) {
            let mut data_bytes = [0u8; 8];
            for j in 0..8 {
                data_bytes[j] = input[32 + i * 8 + j];
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
    println!("Decoded the file in {}ms", ms);
    Ok(())
}

pub fn reconstruct_raw_data(block_id: u64, input_hash_and_xored_data: &Vec<u8>) -> Vec<u8> {
    let group = generate_PoS(
        block_id,
        input_hash_and_xored_data[0..HASH_BYTES_LEN]
            .try_into()
            .unwrap(),
    );

    let mut output: Vec<u8> = Vec::with_capacity(GROUP_BYTE_SIZE);
    // Compute the output : XOR the input with the output of f
    for i in 0..(N * GROUP_SIZE) {
        let mut data_bytes = [0u8; 8];
        for j in 0..8 {
            data_bytes[j] = input_hash_and_xored_data[32 + i * 8 + j];
        }
        let mut data = u64::from_le_bytes(data_bytes);
        data = data ^ group[i / GROUP_SIZE][i % GROUP_SIZE];
        data_bytes = unsafe { transmute(data.to_le()) };
        for j in 0..8 {
            output.push(data_bytes[j]);
        }
    }

    debug!("output === {:?}", output[0..20].to_vec());
    return output;
}