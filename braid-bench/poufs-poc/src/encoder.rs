use std::mem::transmute;
use std::time::Instant;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{Read, SeekFrom};

use blake3;
use aes::Aes128;
use aes::cipher::{
    BlockEncryptMut, KeyIvInit,
    generic_array::GenericArray,
};

use crate::blockgen::{INIT_SIZE, InitGroup, N, GROUP_SIZE, GROUP_BYTE_SIZE, block_gen};

type Aes128Cbc = cbc::Encryptor<Aes128>;

const ID_PUBLIC_KEY: &[u8] = b"727 is a funny number";

pub fn encode(mut input_file: File, mut output_file: File) -> io::Result<()> {
    let startup = Instant::now();

    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    // Compute input and output file sizes
    let input_lenght = input_file.seek(SeekFrom::End(0))?;
    input_file.seek(SeekFrom::Start(0))?;
    let block_count = ((input_lenght - 1) / GROUP_BYTE_SIZE as u64) + 1;
    let output_lenght = 8 + (64 * block_count) + block_count * GROUP_BYTE_SIZE as u64;
    output_file.set_len(output_lenght)?;

    // Write input file size at the start of output file
    let size_bytes: [u8; 8] = unsafe { transmute(input_lenght.to_le()) };
    output_file.write_all(&size_bytes)?;

    // Write blocks
    for i in 0..block_count {
        let mut input = vec![0u8; GROUP_BYTE_SIZE];
        input_file.read(&mut input)?;

        // Compute init vectors
        let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
        for g in 0..GROUP_SIZE {
            let pos_bytes: [u8; 8] = unsafe {
                transmute(((i * GROUP_SIZE as u64) + g as u64).to_le())
            };
            let mut hasher = blake3::Hasher::new();
            hasher.update(&pos_bytes);
            hasher.update(pub_hash.as_bytes());
            let block_hash = hasher.finalize();
            let block_hash = block_hash.as_bytes();
            for i in 0..INIT_SIZE {
                let mut hash_bytes = [0u8; 8];
                for j in 0..8 {
                    hash_bytes[j] = block_hash[i*8 + j]
                }
                inits[i][g] = u64::from_le_bytes(hash_bytes);
            }
        }

        // Compute block_gen
        let group = block_gen(inits);

        // Compute input hash
        let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
        let input_hash = blake3::hash(&input);
        let input_hash = input_hash.as_bytes();
        let key_bytes = GenericArray::from_slice(&input_hash[0..16]);
        let iv_bytes = GenericArray::from_slice(&input_hash[16..32]);
        for i in 0..16 {
            output.push(key_bytes[i]);
        }
        for i in 0..16 {
            output.push(iv_bytes[i]);
        }

        // TODO : Encrypt input with AES using the hash.
        let mut cipher = Aes128Cbc::new(&key_bytes, &iv_bytes);
        for i in 0..(GROUP_BYTE_SIZE / 16) {
            let from = i*16;
            let to = from + 16;
            cipher.encrypt_block_mut(GenericArray::from_mut_slice(&mut input[from..to]));
        }

        // Compute the output : XOR the input with the output of f
        for i in 0..(N*GROUP_SIZE) {
            let mut data_bytes = [0u8; 8];
            for j in 0..8 {
                data_bytes[j] = input[i*8 + j];
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
