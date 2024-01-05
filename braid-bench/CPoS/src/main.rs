mod Merkle_Tree;
mod PoS;
mod block_generation;
mod communication;

extern crate env_logger;
extern crate log;

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::thread;
use std::time::Duration;
// use first_rust_project::Direction;

use rand::Rng;

//use crate::communication::server::start_server;
use crate::block_generation::blockgen::GROUP_SIZE;
use crate::block_generation::encoder::generate_block_group;
use crate::block_generation::utils::Utils::BATCH_SIZE;
use crate::PoS::prover::Prover;
use crate::PoS::verifier::Verifier;

/*
* Possible logger levels are: Error, Warn, Info, Debug, Trace
*/
fn set_logger() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();
}

// fn main(){
//     let avg_step = 7;
//     let mut res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
//     res = rand::thread_rng().gen_range(-avg_step + 1..=avg_step - 1);
//     println!("{}",res);
// }

// block_id == 0 while position == 406227  225

/*A block_group is made of a Vec<[u64,4]>: a Vector containing (2^16 = 65536 elements).
    So in total: there are 2^18 = 262144 u64 elements --> 2^21 = 2097152 u8 elements in a block_group
    A single block is instead made of u8_in_a_block_group/4 = 2^19 = 524288 total bytes
*/
fn main() {
    let is_test = false;
    if is_test {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("TestFile.bin")
            .unwrap();
        let block_group = generate_block_group(0);
        let block: Vec<u64> = block_group[0].to_vec();
        let mut bufu8: Vec<u8> = Vec::new();

        // for &bytesu64 in &block {
        //     let bytes: [u8; 8] = bytesu64.to_be_bytes();
        //     bufu8.extend_from_slice(&bytes);
        // }

        let block_group: Vec<[u64; GROUP_SIZE]> = generate_block_group(0);
        println!("4 Blocks generated");
        println!("block Group len == {}", block_group.len());
        // print!("block_group == {:?}", block_group);
        //println!("block_group[0] == {:?}", block_group[0]);
        let mut metadata = file.metadata();
        println!("length file = {}", metadata.unwrap().len());

        for i in 0..GROUP_SIZE {
            for j in 0..block_group.len() {
                let byte_fragment = block_group[j][i].to_le_bytes();
                file.write_all(&byte_fragment).unwrap();
            }
        }

        // for i in 0..block_group.len() {
        //     let block = block_group[i];
        //     for bytes_fragment in block {
        //         let byte_fragment = bytes_fragment.to_le_bytes();
        //         file.write_all(&byte_fragment).unwrap();
        //     }
        // }

        let metadataa = file.metadata();
        println!("length file = {}", metadataa.unwrap().len());

        //file.write_all(&bufu8).unwrap();

        //file.seek(SeekFrom::Start(0)).unwrap();
        let mut v = Vec::new();
        match file.read_to_end(&mut v) {
            Ok(_) => {}
            Err(e) => {
                print!("error == {:?}", e)
            }
        };

        println!("buffer == {:?} \nof length == {} ", v, v.len());
        let num_u64: u64 = 123456;
        println!("{:?}", num_u64.to_le_bytes());
        println!("{:?}", num_u64.to_ne_bytes());
        let num_u8 = num_u64.to_le_bytes();
        println!("converted == {}", u64::from_le_bytes(num_u8));

        println!("***********************************");
        let mut vec = Vec::new();
        vec.push(1);
        vec.push(2);
        vec.push(3);

        let arr = [1,2,3];

        let harr = blake3::hash(&arr);
        let hvec = blake3::hash(&vec);
        println!("arr == {:?},\nvec == {:?}", harr,hvec);

        let vec1 = vec![121, 42, 92, 135, 49, 186, 219, 126, 247, 25, 118, 177, 21, 79, 159, 252, 58, 185, 38, 205, 11, 82, 212, 176, 218, 91, 127, 156, 100, 213, 116, 29];
        let vec2 = vec![22, 26, 39, 66, 49, 154, 130, 164, 210, 247, 195, 34, 166, 145, 59, 64, 20, 242, 245, 201, 171, 111, 105, 244, 91, 146, 248, 127, 238, 93, 32, 58];

        let mut hasher = blake3::Hasher::new();
        hasher.update(&vec2);
        hasher.update(&vec1);
        println!("FINALIZED == {:?}", hasher.finalize().as_bytes());

        let mut hasherr = blake3::Hasher::new();
        hasherr.update(&vec1);
        hasherr.update(&vec2);
        println!("FINALIZED r == {:?}", hasherr.finalize().as_bytes());

    } else {
        set_logger();
        //challenge: send 1(tag) + 1(seed)
        //let data: [u8, 5] = [255, 1, 7];
        let _data: [u8; 3] = [255, 20, 30];

        let _pub_hash = blake3::hash(b"HELLO");

        let host_prover = String::from("127.0.0.1");
        let port_prover = String::from("3333");
        let address_prover = format!("{}:{}", host_prover, port_prover);

        let host_verifier = String::from("127.0.0.1");
        let port_verifier = String::from("4444");
        let address_verifier = format!("{}:{}", host_verifier, port_verifier);

        println!("Main");
        //let mut prover = Prover::new(address_prover.clone(), address_verifier.clone());
        let addres_prover_clone = address_prover.clone();
        let addres_verifier_clone = address_verifier.clone();

        thread::spawn(move || {
            Prover::start(addres_prover_clone, addres_verifier_clone);
        });
        thread::sleep(Duration::from_secs(5));
        Verifier::start(address_verifier, address_prover);
        thread::sleep(Duration::from_secs(100));
    }
}
