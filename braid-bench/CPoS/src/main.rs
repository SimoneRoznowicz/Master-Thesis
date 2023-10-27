mod server;
mod client;

extern crate log;
extern crate env_logger;
use log::{info, error};

use server::startServer;
use client::startClient;
use std::thread;
use std::time::Duration;


fn main() {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();

    info!("This is an informational message.");
    error!("This is an error message.");

    let sleep_duration = Duration::from_secs(5);
    thread::sleep(sleep_duration);
}
