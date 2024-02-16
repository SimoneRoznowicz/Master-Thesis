use std::io;
use std::path::Path;
use std::fs::File;
use std::process::exit;
use std::env;

mod blockgen;
mod decoder;
mod encoder;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 || (args[1] != "encode" && args[1] != "decode") {
        println!("Usage : poufs <encode|decode> <input_file> <output_file>");
        exit(1);
    }

    let input_file = File::open(Path::new(&args[2]))?;
    let output_file = File::create(Path::new(&args[3]))?;

    if args[1] == "encode" {
        encoder::encode(input_file, output_file)
    } else {
        decoder::decode(input_file, output_file)
    }
}