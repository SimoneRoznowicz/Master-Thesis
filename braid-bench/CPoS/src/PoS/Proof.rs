struct Proof {
    result: bool,
    
}

impl Proof {
    fn new() -> Proof {
        Proof {result: false}
    }

    fn get_result(&self) -> bool {
        return self.result;
    }
    fn set_result(&mut self, newResult: bool) {
        self.result = newResult;
    }
}
