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
    block_gen, InitGroup, GROUP_BYTE_SIZE, GROUP_SIZE, INIT_SIZE, N, BLOCK_BYTE_SIZE,
};
use crate::block_generation::utils::Utils::{NUM_BYTES_IN_BLOCK, NUM_BLOCK_GROUPS_PER_UNIT};

use super::blockgen::BlockGroup;
use super::utils::Utils::{HASH_BYTES_LEN, NUM_BYTES_IN_BLOCK_GROUP, FRAGMENT_SIZE};
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



pub fn encode_orig(mut input_file: File, mut output_file: &File, mut root_hashes: &mut Vec<[u8; HASH_BYTES_LEN]>) -> io::Result<()> {
    // let mut file3 = OpenOptions::new()
    // .create(true)
    // .append(true)
    // .read(true)
    // .write(true)
    // .open("output.txt")
    // .unwrap();
    
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
    // for b in size_bytes{
    //     let bstr = b.to_string() + " ";
    //     file3.write(bstr.as_bytes());
    //     cc += 1;
    // }


    for i in 0..block_count {
        root_hashes.push(generate_commitment_hash(&mut input_file, i as u32));
    }
    debug!("REAL GENERATED ROOT HASHES {:?}",root_hashes);

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

        for i in 0..32 {
            output.push(input_hash[i]);
        }

        // Compute the output : XOR the input with the output of f
        for i in 0..(N*GROUP_SIZE) {
            let mut data_bytes = [0u8; 8];
            for j in 0..8 {
                data_bytes[j] = input[i*8 + j];
            }
            let mut data = u64::from_le_bytes(data_bytes);
            data = data ^ group[i / GROUP_SIZE][i % GROUP_SIZE]; //XOR of Encrypted(raw data) ^ PoS
            data_bytes = unsafe { transmute(data.to_le()) };
            for j in 0..8 {
                output.push(data_bytes[j]);
            }
        }

        // Write to file
        output_file.write_all(&output)?;

        // for b in output{
        //     // if (cc == 64){
        //     //     let ccstr = " * ";
        //     //     file3.write(ccstr.as_bytes());
        //     // }
        //     if cc%10 == 0{
        //         let new_line = "\n";
        //         file3.write(new_line.as_bytes());
        //     }
        //     let bstr = b.to_string() + " ";
        //     file3.write(bstr.as_bytes());
        //     cc += 1;
        // }
    }

    let ttotal = startup.elapsed();
    let ms = ttotal.as_micros() as f32 / 1_000.0;
    println!("Encoded the file in {}ms", ms);
    Ok(())
}


pub fn generate_xored_data(block_id: u32, position: u32, root_hash: [u8;HASH_BYTES_LEN], self_fragment: [u8; FRAGMENT_SIZE], flag: bool) -> Vec<u8>{
    // Compute input hash
    let group = generate_PoS(block_id as u64, root_hash);
    let mut input = vec![0u8; GROUP_BYTE_SIZE];
    debug!("posssition =={}", position);
    let mut number_id_fragment = position / HASH_BYTES_LEN as u32;
    let mut indx_start = (number_id_fragment) as usize * HASH_BYTES_LEN; //layer_len % HASH_BYTES_LEN;

    // let indx_start = position / FRAGMENT_SIZE as u32;
    let indx_end = indx_start+FRAGMENT_SIZE;

    let mut k=0;
    for i in indx_start..indx_end {
        debug!("k nel ciclo =={} mentre current value è {} e self_fragment[k] è {}",k,input[i], self_fragment[k]);
        input[i as usize] = self_fragment[k];
        k+=1;
    }

    debug!("indx_start == {:?}, indx_end == {}", indx_start, indx_end);

    debug!("self_fragment == {:?}", self_fragment);
    let part_input = &input[indx_start as usize..indx_end as usize+5];
    debug!("Input == {:?}", part_input);

    let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
    let input_hash = root_hash;

    for i in 0..32 {
        output.push(input_hash[i]);
    }

    // Compute the output : XOR the input with the output of f
    let mut flag = false;
    let margin = (position as u32/8 as u32) as usize;
    debug!("Just before printing...");
    for i in 0..(N*GROUP_SIZE) {
        // if i == margin || i == margin+1 || i == margin+2{
        //     flag =true;
        // }
        let mut data_bytes = [0u8; 8];
        for j in 0..8 {
            data_bytes[j] = input[i*8 + j];
        }
        let mut data = u64::from_le_bytes(data_bytes);
        if data != 0 {
            flag = true;
            debug!("\n V Index i*8 =={} data_bytes =={:?},\n data u64 == {}",i*8, data_bytes,data);
        }
        
        data = data ^ group[i / GROUP_SIZE][i % GROUP_SIZE]; //XOR of Encrypted(raw data) ^ PoS
        data_bytes = unsafe { transmute(data.to_le()) };
        if flag {
            debug!("\n V AFTER: Index i*8 =={} data_bytes =={:?},\n data u64 == {}",i*8, data_bytes,data);
        }

        for j in 0..8 {
            output.push(data_bytes[j]);
        }
        flag = false;
    }

    if flag == true{
        let mut file3 = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .write(true)
            .open("generated_almost_empty_out.txt")
            .unwrap();

        let mut cc = 0;
        for b in 0..output.len(){
            let bstr = output[b].to_string() + " ";
            file3.write(bstr.as_bytes());
        }
    }
    return output[HASH_BYTES_LEN+indx_start as usize..HASH_BYTES_LEN+indx_end as usize].to_vec();
}


// pub fn generate_xored_data_prover(block_id: u32, position: u32, root_hash: [u8;HASH_BYTES_LEN], self_fragment: [u8; FRAGMENT_SIZE], flag: bool, mut input: Vec<u8>) -> Vec<u8>{
//     // Compute input hash
//     let group = generate_PoS(block_id as u64, root_hash);

//     //let input = vec![0u8; GROUP_BYTE_SIZE];
//     debug!("posssition prover =={}", position);

//     let mut number_id_fragment = position / HASH_BYTES_LEN as u32;
//     let mut indx_start = (number_id_fragment) as usize * HASH_BYTES_LEN; //layer_len % HASH_BYTES_LEN;


//     //let indx_start = position / FRAGMENT_SIZE as u32;
//     let indx_end = indx_start+FRAGMENT_SIZE;
    
//     let part_input = &input[indx_start as usize..indx_end as usize];
//     debug!("Input before == {:?}", part_input);
//     debug!("indx_start == {:?} and indx_end == {:?}", indx_start,indx_end);

//     let mut k = 0;
    
//     // //TO REMOVE
//     // let mut x = indx_start/1000;
//     // while x<(indx_start/100) {
//     //     input[x] = 0;
//     //     x+=1;
//     // }
//     // debug!("x == {}",x);

//     // //END TO REMOVE
    
//     for i in indx_start..indx_end {
//         debug!("k nel ciclo =={} mentre current value è {} e self_fragment[k] è {}",k,input[i], self_fragment[k]);
//         input[i as usize] = self_fragment[k];
//         k+=1;
//     }
    
//     //TO REMOVE!!
//     // input[50] = 0;
//     // input[0] = 0;

    
    
//     debug!("self_fragment == {:?}", self_fragment);
//     let part_input = &input[indx_start as usize..indx_end as usize];
//     debug!("Input == {:?}", part_input);

//     let mut output: Vec<u8> = Vec::with_capacity(32 + GROUP_BYTE_SIZE);
//     let input_hash = root_hash;


//     for i in 0..32 {
//         output.push(input_hash[i]);
//     }

//     // let key_bytes: &GenericArray<u8, aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UTerm, aes::cipher::typenum::B1>, aes::cipher::typenum::B0>, aes::cipher::typenum::B0>, aes::cipher::typenum::B0>, aes::cipher::typenum::B0>> = GenericArray::from_slice(&input_hash[0..16]);
//     // let iv_bytes: &GenericArray<u8, aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UInt<aes::cipher::typenum::UTerm, aes::cipher::typenum::B1>, aes::cipher::typenum::B0>, aes::cipher::typenum::B0>, aes::cipher::typenum::B0>, aes::cipher::typenum::B0>> = GenericArray::from_slice(&input_hash[16..32]);
//     // for i in 0..16 {
//     //     output.push(input_hash[0..16]);
//     // }
//     // for i in 0..16 {
//     //     output.push(input_hash[i]);
//     // }
// //6, 223, 66, 203, 214, 21, 5, 66, 181, 190, 222, 239, 37, 148, 182, 90, 117, 81, 152, 118, 192, 97, 213, 41, 156, 18, 202, 141, 230, 100, 234, 81]
    
//     // TODO : Encrypt input with AES using the hash.
//     // let mut cipher = Aes128Cbc::new(&key_bytes, &iv_bytes);
//     // for i in 0..(GROUP_BYTE_SIZE / 16) {
//     //     let from = i*16;
//     //     let to = from + 16;
//     //     cipher.encrypt_block_mut(GenericArray::from_mut_slice(&mut input[from..to]));
//     // }

//     // Compute the output : XOR the input with the output of f
//     let mut flag = false;
//     let margin = (position as u32/8 as u32) as usize;
//     for i in 0..(N*GROUP_SIZE) {
//         if i*8 == indx_start || i*8 == indx_start+8 || i*8 == indx_start+16 || i*8 == indx_start+24 {
//             flag =true;
//         }
//         let mut data_bytes = [0u8; 8];
//         for j in 0..8 {
//             data_bytes[j] = input[i*8 + j];
//         }
//         let mut data = u64::from_le_bytes(data_bytes);
//         if flag {
//             debug!("\n P Index i*8 =={} data_bytes =={:?},\n data u64 == {}",i*8, data_bytes,data);
//         }
//         data = data ^ group[i / GROUP_SIZE][i % GROUP_SIZE]; //XOR of Encrypted(raw data) ^ PoS
//         data_bytes = unsafe { transmute(data.to_le()) };
//         for j in 0..8 {
//             output.push(data_bytes[j]);
//         }
//         flag = false;
//     }


//     if flag == true{
//         let mut file3 = OpenOptions::new()
//             .create(true)
//             .append(true)
//             .read(true)
//             .write(true)
//             .open("generated_almost_empty_out.txt")
//             .unwrap();

//         let mut cc = 0;
//         for b in 0..output.len(){
//             let bstr = output[b].to_string() + " ";
//             file3.write(bstr.as_bytes());
//         }
//     }
//     return output[HASH_BYTES_LEN+indx_start as usize..HASH_BYTES_LEN+indx_end as usize].to_vec();
// }









pub fn generate_PoS(block_id: u64, root_hash: [u8;HASH_BYTES_LEN]) -> BlockGroup {
    let pub_hash = blake3::hash(ID_PUBLIC_KEY);

    // Compute init vectors
    let mut inits: InitGroup = [[0; GROUP_SIZE]; INIT_SIZE];
    for g in 0..GROUP_SIZE {
        let pos_bytes: [u8; 8] = unsafe {
            transmute(((block_id * GROUP_SIZE as u64) + g as u64).to_le())
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pos_bytes);
        hasher.update(pub_hash.as_bytes());
        hasher.update(&root_hash);

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
    return group;
}