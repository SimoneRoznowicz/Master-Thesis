use core::time;
use std::io::Write;
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;

extern crate env_logger;
extern crate log;
use log::error;

pub fn send_msg(mut stream: &TcpStream, msg: &[u8]) {
    sleep(Duration::from_millis(20));  //100km single direction delay 
    match stream.write(msg) {
        Ok(_) => {
            stream.flush();
        }
        Err(_) => {
            error!("Message not sent correctly!")
        }
    };
}
