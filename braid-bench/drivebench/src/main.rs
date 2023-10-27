use std::{env, io, process::exit};

mod generate;
mod drivebench;

fn main() -> io::Result<()> {

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || (args[1] != "generate" && args[1] != "benchmark") {
        println!("Usage : drivebench <generate|benchmark>");
        exit(1);
    }

    if args[1] == "generate" {
        generate::generate()
    } else {
        drivebench::benchmark()
    }
}