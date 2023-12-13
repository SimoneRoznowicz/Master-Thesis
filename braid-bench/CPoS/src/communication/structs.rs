#[derive(Debug, Copy, Clone)]
pub enum Notification {
    Start,
    Stop,
    Update,
    Verification_Time,
    Verification_Correctness,
    Create_Inclusion_Proofs,
    Handle_Inclusion_Proof,
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
    Fair,
    Unfair(Failure_Reason),
}

#[derive(Debug, Clone)]
pub enum Failure_Reason {
    Time,
    Correctness,
}

#[derive(Debug, Clone)]
pub enum Time_Verification_Status {
    Insufficient_Proofs,
    Correct,
    Incorrect,
}
