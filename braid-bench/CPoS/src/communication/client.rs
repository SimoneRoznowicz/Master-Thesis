use std::io::Write;
use std::net::TcpStream;

extern crate env_logger;
extern crate log;
use log::error;

pub fn send_msg(mut stream: &TcpStream, msg: &[u8]) {
    match stream.write(msg) {
        Ok(_) => {
            stream.flush();
        }
        Err(_) => {
            error!("Message not sent correctly!")
        }
    };
}

// pub fn send_msg_prover(stream_opt: &Arc<Mutex<Option<TcpStream>>>, msg: &[u8]) {
//     warn!("Starting send_msg_prover");
//     let stream_opt_clone = stream_opt.clone();

//     let locked_stream: std::sync::MutexGuard<'_, Option<TcpStream>> =
//         stream_opt_clone.lock().unwrap(); //stream_opt.lock().unwrap().as_ref().clone();
//     warn!("After lock");
//     let _xx = locked_stream.as_ref().unwrap();
//     match locked_stream.as_ref().unwrap().write(msg) {
//         Ok(_) => {
//             locked_stream.as_ref().unwrap().flush();
//             //info!("Message correctly sent from {} to {}", locked_stream.unwrap().local_addr().unwrap().to_string(), locked_stream.unwrap().peer_addr().unwrap().to_string());
//             info!("PROVER writes: Message written is {}", msg[0]);
//         }
//         Err(_) => {
//             error!("Message not sent correctly!")
//         }
//     };
// }
