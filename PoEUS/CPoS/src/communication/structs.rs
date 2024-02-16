#[derive(Debug, Clone)]
pub struct NotifyNode {
    pub buff: Vec<u8>,
    pub notification: Notification,
}

impl NotifyNode {
    pub fn new(buff: Vec<u8>, variant: Notification) -> NotifyNode {
        NotifyNode {
            buff,
            notification: variant, // Replace with your actual variant
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Notification {
    Start,
    Stop,
    Update,
    Collect_Block_Hashes,
    Verification_Time,
    Verification_Correctness,
    Create_Inclusion_Proofs,
    Handle_Inclusion_Proof,
    Handle_Prover_commitment,
    Terminate,
}

#[derive(Debug, Clone)]
pub enum Verification_Status {
    Executing,
    Terminated,
}

#[derive(Debug, Clone)]
pub enum Fairness {
    Undecided,
    Successful,
    Failure(Failure_Reason),
}

#[derive(Debug, Clone)]
pub enum Failure_Reason {
    Timeout,
    Incorrect,
}

#[derive(Debug, Clone)]
pub enum Time_Verification_Status {
    Insufficient_Proofs,
    Correct,
    Incorrect,
}