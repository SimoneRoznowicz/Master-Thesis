use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::Read;
use std::io::SeekFrom;

use rand::prelude::*;

use std::time::Instant;

const WARMUP_COUNT: usize = 10000;
const ITER_COUNT: usize = 100000;

const FILE_SIZE_E: usize = 6 + 30; // 64 GB
const READ_SIZE_E: usize = 3; // 8 Bytes = 64 bits
const READ_INDEX_SIZE_E: usize = FILE_SIZE_E - READ_SIZE_E;
const READ_SIZE: usize = 1 << READ_SIZE_E;

pub fn benchmark() -> io::Result<()> {
    let mut rng = rand::thread_rng();
    let mut ofile = File::open("./random-data.bin")?;

    let mut buf = [0u8; READ_SIZE];
    for _ in 0..WARMUP_COUNT {
        let value = rng.next_u64();
        ofile.seek(SeekFrom::Start((value >> (64 - READ_INDEX_SIZE_E)) << READ_SIZE_E))?;
        ofile.read(&mut buf)?;
    }
    let mut lowest = 1000u128;
    let mut highest = 0u128;
    let threshold = 20u128; // Ignore cached values
    let start = Instant::now();
    for _ in 0..ITER_COUNT {
        let start = Instant::now();
        let r = u64::from_le_bytes(buf);
        let value = rng.next_u64() ^ r;
        ofile.seek(SeekFrom::Start((value >> (64 - FILE_SIZE_E + READ_SIZE_E)) << READ_SIZE_E))?;
        ofile.read(&mut buf)?;
        let time = start.elapsed().as_micros();
        if lowest > time && time > threshold { lowest = time; }
        if highest < time { highest = time; }
    }
    let time = start.elapsed().as_millis();
    println!("{}ms for {} iterations. Lowest : {}μs, Highest : {}μs.", time, ITER_COUNT, lowest, highest);
    Ok(())
}
