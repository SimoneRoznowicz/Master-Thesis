pub enum Phase {
    Init,
    Challenge,
    Execute,
    Verify,
}

#[derive(Debug,Copy,Clone)]
pub enum Notification {
    Continue,
    Stop,
    Verification,
}

