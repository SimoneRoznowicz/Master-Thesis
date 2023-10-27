#![recursion_limit="50000"]
use std::time::Instant;

use crate::blockgen::{INIT_SIZE, N};

mod blockgen;

const RUNS: usize = 5;
const ITER: usize = 128;

fn main() {
    // println!("E = {}, D = {}, N = {}", block::E, block::D, block::N);
    // println!("SPEEDUP = {}", block::MAX_SPEEDUP);
    // println!("SIZE = {} ~= {}N", block::SIZE, block::SIZE / block::N);
    // println!("STEPS = {}", block::STEPS);
    println!("Block count per group : {}", blockgen::GROUP_SIZE);
    println!("Group size : {}MiB", (blockgen::GROUP_BYTE_SIZE/1024) as f32 / 1024.0);
    // let mut x: block::BlockGroup = vec![[0; block::GROUP_SIZE]; block::INIT_SIZE];
    let mut x: blockgen::InitGroup = [[0; blockgen::GROUP_SIZE]; blockgen::INIT_SIZE];
    for j in 0..blockgen::INIT_SIZE {
        for i in 0..blockgen::GROUP_SIZE {
            x[j][i] = (j * blockgen::GROUP_SIZE + i + 727) as blockgen::FRAGMENT;
        }
    }
    for _ in 0..ITER {
        let res = blockgen::block_gen(x);
        // Chain computations to avoid optimizations :
        for j in 0..INIT_SIZE {
            x[j] = res[N - 1 - j];
        }
    }
    println!("Warmup done.");
    for _ in 0..RUNS {
        let start = Instant::now();
        for _ in 0..ITER {
            let res = blockgen::block_gen(x);
            // Chain computations to avoid optimizations :
            for j in 0..INIT_SIZE {
                x[j] = res[N - 1 - j];
            }
        }
        let t = start.elapsed();
        let ms = (t.as_micros() / ITER as u128) as f32 / 1_000.0;
        println!("Runtime per block = {:.2}ms", ms);
        println!("Read speed = {:.2}MB/s", (blockgen::GROUP_BYTE_SIZE * 1_000) as f32 / (ms * (1 << 20) as f32));
        println!("\"Clock speed\" = {:.2}GHz", (blockgen::STEPS * blockgen::GROUP_SIZE) as f32 / (ms * 1_000_000.0));
    }
    println!("x = {:?}", x);
}
