use crate::communication::client::start_client;


fn challenge(uint: c) {
    let val = String::from(c);    
    start_client()
}

fn verify() -> bool{
    return true;
}