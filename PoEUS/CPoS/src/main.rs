mod Merkle_Tree;
mod PoS;
mod block_generation;
mod communication;

extern crate env_logger;
extern crate log;

use std::time::Duration;
use std::{env, thread};

use log::LevelFilter;

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
    env_logger::builder().filter_level(level).init();
}

fn main() {
    /* Uncomment the following if you want the logs to be saved in a file instead of a
    let target = Box::new(File::create("log.txt").expect("Can't create file"));

    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(target))
        .filter(None, LevelFilter::Debug)
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {} {}:{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();
    */
    let args: Vec<String> = env::args().collect();
    println!("arr == {:?}", args);

    set_logger(args[1].to_lowercase());

    let address_prover = format!("{}:{}", String::from("127.0.0.1"), String::from("3333"));

    let addres_prover_clone = address_prover.clone();

    thread::spawn(move || {
        Prover::start(addres_prover_clone);
    });

    Verifier::start(address_prover);
    thread::sleep(Duration::from_secs(1000));
}
