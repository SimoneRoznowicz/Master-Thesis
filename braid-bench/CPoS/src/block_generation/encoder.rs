use std::fs::{File, OpenOptions, Permissions};
use std::io;
use std::io::prelude::*;
use std::io::{Read, SeekFrom};
use std::mem::transmute;
use std::time::Instant;

use aes::cipher::{generic_array::GenericArray, BlockEncryptMut, KeyIvInit};
use aes::Aes128;
use blake3;
use log::{debug,error};

use crate::PoS::prover::read_block_from_input_file;
use crate::block_generation::blockgen::{
    block_gen, InitGroup, GROUP_BYTE_SIZE, GROUP_SIZE, INIT_SIZE, N,
};
use crate::block_generation::utils::Utils::{NUM_BYTES_IN_BLOCK, NUM_BLOCK_GROUPS_PER_UNIT};

use super::blockgen::BlockGroup;
use super::utils::Utils::{HASH_BYTES_LEN, NUM_BYTES_IN_BLOCK_GROUP};
type Aes128Cbc = cbc::Encryptor<Aes128>;

const ID_PUBLIC_KEY: &[u8] = b"727 is a funny number";


pub fn generate_commitment_hash (
    input_file: &mut File,
    block_id: u32,
) -> [u8; 32] {

    let mut buffer = vec![0; NUM_BYTES_IN_BLOCK_GROUP as usize];
    read_block_from_input_file(input_file, block_id, &mut buffer);

    let mut hash_layers: Vec<u8> = buffer.to_vec();
    let mut root_hash: [u8; HASH_BYTES_LEN] = [0; HASH_BYTES_LEN];
    
    let mut i = 0;
    let _counter = 0;
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


// pub fn encode(mut input_file: File, mut output_file: &File, mut root_hashes: &mut Vec<[u8; 32]>) -> io::Result<()> {
//     let startup = Instant::now();
//     debug!("Arrived here");
//     let pub_hash = blake3::hash(ID_PUBLIC_KEY);
//     // Compute input and output file sizes
//     let input_lenght = input_file.seek(SeekFrom::End(0))?;
//     debug!("Arrived here");

//     let input_lenght = input_file.seek(SeekFrom::End(0))?;
//     input_file.seek(SeekFrom::Start(0))?;
//     let block_count = ((input_lenght - 1) / GROUP_BYTE_SIZE as u64) + 1;
//     unsafe { NUM_BLOCK_GROUPS_PER_UNIT = block_count };

//     // let mut root_hashes: Vec<[u8; 32]> = Vec::new();
//     for i in 0..block_count {
//         root_hashes.push(generate_commitment_hash(&mut input_file, i as u32));
//     }
//     input_file.seek(SeekFrom::Start(0))?;

//     let output_lenght = 8 + (64 * block_count) + block_count * GROUP_BYTE_SIZE as u64;
//     output_file.set_len(output_lenght)?;


//     error!("output_length breakdown:\n8\n(64 * block_count) == {}\nGROUP_BYTE_SIZE as u64 == {}",64 * block_count,block_count*GROUP_BYTE_SIZE as u64);
//     error!("Remaining: output_length % block_length == {}", output_lenght%NUM_BYTES_IN_BLOCK as u64);


//         let mut file3 = OpenOptions::new()
//         .create(true)
//         .append(true)
//         .read(true)
//         .write(true)
//         .open("output.txt")
//         .unwrap();
//     // Output file made of (in order):

//     // QUESTO CONTA PER LA COMPOSIZIONE DEL FILE OUTPUT:
//     // 8 bytes file size
//     // for block (blockgroup) in blocks
//     //      - 32 byte: hash of a block of data contained in the input
//     //      - NUM_BYTES_IN_BLOCK_GROUP bytes of XORed data + CPoS of the block


//     // 64 bytes for each block
//     // block data (encrypted and XOred) for each block
//     // 

//     // Write input file size at the start of output file
//     let size_bytes: [u8; 8] = unsafe { transmute(input_lenght.to_le()) };
//     output_file.write_all(&size_bytes).unwrap();
//         let mut cc = 0;
//         for b in size_bytes{
//             let bstr = b.to_string() + " ";
//             file3.write(bstr.as_bytes());
//             cc += 1;
//         }

//     // Write blocks
//     for i in 0..block_count {
//         let mut input = vec![0u8; GROUP_BYTE_SIZE];
//         input_file.read(&mut input)?;

//         // Compute init vectors
//         let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
//         for g in 0..GROUP_SIZE {
//             let pos_bytes: [u8; 8] =
//                 unsafe { transmute(((i * GROUP_SIZE as u64) + g as u64).to_le()) };
//             let mut hasher = blake3::Hasher::new();
//             hasher.update(&pos_bytes);
//             hasher.update(pub_hash.as_bytes());
//             //hasher.update(&root_hashes[i as usize]);  //hash.as_bytes() del block i

//             let block_hash = hasher.finalize();
//             let block_hash = block_hash.as_bytes();
//             for i in 0..INIT_SIZE {
//                 let mut hash_bytes = [0u8; 8];
//                 for j in 0..8 {                             
//                     hash_bytes[j] = block_hash[i * 8 + j]
//                 }
//                 inits[i][g] = u64::from_le_bytes(hash_bytes);
//             }
//         }

//         // Compute block_gen
//         let group = block_gen(inits);

//         // // Compute input hash  ORIGINAL
//         let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
//         let input_hash = blake3::hash(&input);  //compute input hash with the merkle tree
//         let input_hash = input_hash.as_bytes();
//         debug!("input hash of blockgroup number {} is {:?}", i,input_hash);

//         let key_bytes = GenericArray::from_slice(&input_hash[0..16]);
//         let iv_bytes = GenericArray::from_slice(&input_hash[16..32]);
//         for i in 0..16 {
//             output.push(key_bytes[i]);
//         }
//         for i in 0..16 {
//             output.push(iv_bytes[i]);
//         }

//         // Compute input hash  MODIFIED
//         // let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
//         // let input_hash = root_hashes[i as usize];
//         // debug!("input hash of blockgroup number {} is {:?}", i,input_hash);

//         // let key_bytes = GenericArray::from_slice(&input_hash[0..16]);
//         // let iv_bytes = GenericArray::from_slice(&input_hash[16..32]);
//         // for i in 0..16 {
//         //     output.push(key_bytes[i]);
//         // }
//         // for i in 0..16 {
//         //     output.push(iv_bytes[i]);
//         // }



//         // TODO : Encrypt input with AES using the hash.
//         let mut cipher = Aes128Cbc::new(&key_bytes, &iv_bytes);
//         for i in 0..(GROUP_BYTE_SIZE / 16) {
//             let from = i * 16;
//             let to = from + 16;
//             cipher.encrypt_block_mut(GenericArray::from_mut_slice(&mut input[from..to]));
//         }

//         // Compute the output : XOR the input with the output of f
//         for i in 0..(N * GROUP_SIZE) {
//             let mut data_bytes = [0u8; 8];
//             for j in 0..8 {
//                 data_bytes[j] = input[i * 8 + j];
//             }
//             let mut data = u64::from_le_bytes(data_bytes);
//             data = data ^ group[i / GROUP_SIZE][i % GROUP_SIZE];
//             data_bytes = unsafe { transmute(data.to_le()) };
//             for j in 0..8 {
//                 output.push(data_bytes[j]);
//             }
//         }

//         // Write to file
//             debug!("IN ENCODE: output == {:?}", output[0]);
//             output_file.write_all(&output).unwrap();

//         for b in output{
//             if (cc == 64){
//                 let ccstr = " * ";
//                 file3.write(ccstr.as_bytes());
//             }
//             if cc%10 == 0{
//                 let new_line = "\n";
//                 file3.write(new_line.as_bytes());
//             }
//             let bstr = b.to_string() + " ";
//             file3.write(bstr.as_bytes());
//             cc += 1;
//         }
//     }

//     let ttotal = startup.elapsed();
//     let ms = ttotal.as_micros() as f32 / 1_000.0;
//     println!("Encoded the file in {}ms", ms);


//     output_file.seek(SeekFrom::Start(0));
//     // let mut buffer_hash_block_output = [0; 100];
//     // match output_file.read_exact(&mut buffer_hash_block_output) {
//     //     Ok(_) => {}
//     //     Err(e) => {
//     //         error!("Error reading file == {:?}", e)
//     //     }
//     // };
//     // debug!("IN ENCODE: output saved hash == {:?}", buffer_hash_block_output);


//     Ok(())
// }












pub fn generate_block_group(i: u64) -> BlockGroup {
    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
    for g in 0..GROUP_SIZE {
        let pos_bytes: [u8; 8] = unsafe { transmute(((i * GROUP_SIZE as u64) + g as u64).to_le()) };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pos_bytes);
        hasher.update(pub_hash.as_bytes());
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
    return block_gen(inits);
}


pub fn generate_block(i: u64) -> BlockGroup {
    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
    for g in 0..GROUP_SIZE {
        let pos_bytes: [u8; 8] = unsafe { transmute(((i * GROUP_SIZE as u64) + g as u64).to_le()) };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pos_bytes);
        hasher.update(pub_hash.as_bytes());
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
    return block_gen(inits);
}









pub fn encode_orig(mut input_file: File, mut output_file: &File, mut root_hashes: &mut Vec<[u8; 32]>) -> io::Result<()> {
    let mut file3 = OpenOptions::new()
    .create(true)
    .append(true)
    .read(true)
    .write(true)
    .open("output.txt")
    .unwrap();
    
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
    for b in size_bytes{
        let bstr = b.to_string() + " ";
        file3.write(bstr.as_bytes());
        cc += 1;
    }


    for i in 0..block_count {
        root_hashes.push(generate_commitment_hash(&mut input_file, i as u32));
    }
    input_file.seek(SeekFrom::Start(0))?;

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
            hasher.update(&root_hashes[i as usize]);

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
        let input_hash = root_hashes[i as usize];

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

        for b in output{
            if (cc == 64){
                let ccstr = " * ";
                file3.write(ccstr.as_bytes());
            }
            if cc%10 == 0{
                let new_line = "\n";
                file3.write(new_line.as_bytes());
            }
            let bstr = b.to_string() + " ";
            file3.write(bstr.as_bytes());
            cc += 1;
        }
    }

    let ttotal = startup.elapsed();
    let ms = ttotal.as_micros() as f32 / 1_000.0;
    println!("Encoded the file in {}ms", ms);
    Ok(())
}