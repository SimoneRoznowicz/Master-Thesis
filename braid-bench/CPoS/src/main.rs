mod communication;
mod PoS;
mod block_generation;


extern crate log;
extern crate env_logger;
use log::{info, error};

use std::thread;
use std::time::Duration;
use crate::communication::client::start_client;
use crate::communication::server::start_server;

/*
* Possible logger levels are: Error, Warn, Info, Debug, Trace
*/
fn set_logger(){
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
}

fn main() {
    set_logger();
    //info!("This is an informational message.");
    //error!("This is an error message.");
    //start_client();
    let sleep_duration = Duration::from_secs(5);
    thread::sleep(sleep_duration);
}
