mod Merkle_Tree;
mod PoS;
mod block_generation;
mod communication;

extern crate env_logger;
extern crate log;

use std::fs::{OpenOptions, self, File};
use std::io::{Read, Write};
use std::{thread, env};
use std::time::Duration;
// use first_rust_project::Direction;

use chrono::Local;
use log::{info, LevelFilter, debug};

//use crate::communication::server::start_server;
use crate::block_generation::blockgen::GROUP_SIZE;
use crate::block_generation::encoder::generate_block_group;

use crate::PoS::prover::Prover;
use crate::PoS::verifier::Verifier;

/*
* Possible logger levels are: Error, Warn, Info, Debug, Trace
*/
fn set_logger(level_filter: String) {
    let level: LevelFilter;
    if level_filter == "trace" {
        level = LevelFilter::Trace;
    } else if level_filter == "debug" {
        level = LevelFilter::Debug;
    } else if level_filter == "info" {
        level = LevelFilter::Info;
    } else if level_filter == "warn" {
        level = LevelFilter::Warn;
    } else if level_filter == "error" {
        level = LevelFilter::Error;
    } else {
        level = LevelFilter::Off;
    }
    env_logger::builder()
        .filter_level(level)
        .init();
}

// block_id == 0 while position == 406227  225

/*A block_group is made of a Vec<[u64,4]>: a Vector containing (2^16 = 65536 elements).
    So in total: there are 2^18 = 262144 u64 elements --> 2^21 = 2097152 u8 elements in a block_group
    A single block is instead made of u8_in_a_block_group/4 = 2^19 = 524288 total bytes
*/
fn main() {
    let is_test = false;
    if is_test {
        match fs::remove_file("test_main.bin") {
            Ok(()) => {
                info!("Previous file removed successfully.");
            }
            Err(err) => {
                eprintln!("Error removing file: {:?}", err);
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("TestFile.bin")
            .unwrap();
        let block_group = generate_block_group(0);
        let _block: Vec<u64> = block_group[0].to_vec();
        let _bufu8: Vec<u8> = Vec::new();

        let block_group: Vec<[u64; GROUP_SIZE]> = generate_block_group(0);
        println!("4 Blocks generated");
        println!("block Group len == {}", block_group.len());
        // print!("block_group == {:?}", block_group);
        //println!("block_group[0] == {:?}", block_group[0]);
        let metadata = file.metadata();
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

        let arr = [1, 2, 3];

        let harr = blake3::hash(&arr);
        let hvec = blake3::hash(&vec);
        println!("arr == {:?},\nvec == {:?}", harr, hvec);

        let vec1 = vec![
            121, 42, 92, 135, 49, 186, 219, 126, 247, 25, 118, 177, 21, 79, 159, 252, 58, 185, 38,
            205, 11, 82, 212, 176, 218, 91, 127, 156, 100, 213, 116, 29,
        ];
        let vec2 = vec![
            22, 26, 39, 66, 49, 154, 130, 164, 210, 247, 195, 34, 166, 145, 59, 64, 20, 242, 245,
            201, 171, 111, 105, 244, 91, 146, 248, 127, 238, 93, 32, 58,
        ];

        let mut hasher = blake3::Hasher::new();
        hasher.update(&vec2);
        hasher.update(&vec1);
        println!("FINALIZED == {:?}", hasher.finalize().as_bytes());

        let mut hasherr = blake3::Hasher::new();
        hasherr.update(&vec1);
        hasherr.update(&vec2);
        println!("FINALIZED r == {:?}", hasherr.finalize().as_bytes());
    } else {
        // let target = Box::new(File::create("log.txt").expect("Can't create file"));

        // env_logger::Builder::new()
        //     .target(env_logger::Target::Pipe(target))
        //     .filter(None, LevelFilter::Debug)
        //     .format(|buf, record| {
        //         writeln!(
        //             buf,
        //             "[{} {} {}:{}] {}",
        //             Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
        //             record.level(),
        //             record.file().unwrap_or("unknown"),
        //             record.line().unwrap_or(0),
        //             record.args()
        //         )
        //     })
        //     .init();
        // debug!("hello");
        // info!("Simone");

        let args: Vec<String> = env::args().collect();
        println!("arr == {:?}", args);

        set_logger(args[1].to_lowercase());
        println!("arr == {}", args[1]);


        let address_prover = format!("{}:{}", String::from("127.0.0.1"),String::from("3333"));

        println!("Main");
        let addres_prover_clone = address_prover.clone();

        thread::spawn(move || {
            Prover::start(addres_prover_clone);
        });

        Verifier::start(address_prover);
        thread::sleep(Duration::from_secs(100));
    }
}
