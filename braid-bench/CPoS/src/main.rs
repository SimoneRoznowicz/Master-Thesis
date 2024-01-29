mod Merkle_Tree;
mod PoS;
mod block_generation;
mod communication;

extern crate env_logger;
extern crate log;

use std::fs::{OpenOptions, self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::{thread, env};
use std::time::{Duration, Instant};
// use first_rust_project::Direction;

use chrono::Local;
use log::{info, LevelFilter, debug};

//use crate::communication::server::start_server;
use crate::block_generation::blockgen::GROUP_SIZE;

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

fn count_elements(target: u32, good_elem: u32, bad_elem: u32) -> (u32, u32) {
    let mut sum = 0;
    let mut iter = 0;
    let mut good_count = 0;
    let mut bad_count = 0;
    while iter<10{
        if sum < target {
            sum += bad_elem;
            bad_count +=1;
        } else {
            sum += good_elem;
            good_count +=1;
        }
        iter+=1;
    }
    //let's be more precise, maybe  overestimated the bad proofs number
    if sum >= target+bad_count{
        good_count+=1;
        bad_count-=1;
        sum = sum + good_count - bad_count;
    }
    
    return (good_count,bad_count);
}


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
        let target = 22007;
        let good_elem = 7;
        let bad_elem = 20;    //140+21= 161
        //120+28 = 148
        let (good_elem, bad_elem) = count_elements(target,good_elem,bad_elem);
        println!("Number of good_elem: {}", good_elem);
        println!("Number of bad_elem : {}", bad_elem);
    
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





/*
    // let time_start;
    // {
    //     time_start = shared_time_start.lock().unwrap().to_owned();
    // }
    // let delta_time = (time_curr-time_start).as_micros();
    // error!("proofs len == {}", proofs.len());
    // error!("delta time == {}", delta_time);

    // let (good_proof_count,bad_proof_count) = count_elements(proofs.len(), delta_time, GOOD_PROOF_AVG_TIMING, BAD_PROOF_AVG_TIMING);
    // let p = good_proof_count as f64 / (bad_proof_count+good_proof_count) as f64;
    // let std = (1.0/(proofs.len() as f64).sqrt())*(p*(1.0-p)).sqrt();
    // let inf =-2.576*std+p;
    // let sup = 2.576*std+p;
    // error!("inf == {} and sup == {}", inf,sup);
    // error!("good_proof_count == {}", good_proof_count);
    // error!("bad_proof_count == {}", bad_proof_count);
    // error!("p == {}", p);

    // if sup-inf < 0.08 {
    //     if (sup+inf)/2.0 >= LOWEST_ACCEPTED_STORING_PERCENTAGE as f64{
    //         error!("**Stop Verification time Successful");
    //         return Time_Verification_Status::Correct;
    //     }
    //     error!("Stop Verification time FAILED");
    //     return Time_Verification_Status::Incorrect;
    // }

*/