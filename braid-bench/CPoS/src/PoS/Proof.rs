struct Proof {
    result: bool,
}

impl Proof {
    fn new() -> Proof {
        Proof {result: false}
    }
    fn get_result(&self) -> u64 {
        self.result
    }
    fn set_result(&mut self, bool: newResult) -> u64 {
        self.result = newResult;
    }
}
