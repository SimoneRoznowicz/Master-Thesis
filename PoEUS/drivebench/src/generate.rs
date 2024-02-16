use std::fs::File;
use std::io::Write;
use std::io;

use rand::prelude::*;
use std::mem::transmute;

use num_cpus;
use threadpool::ThreadPool;
use std::sync::mpsc::sync_channel;


const CHUNK_SIZE: usize = 1usize << 15;
const ITER_COUNT: usize = 1usize << 10;
const JOB_COUNT: usize = 1usize << 8;

const BUFFER_SIZE: usize = CHUNK_SIZE * 8;

const TOTAL_SIZE: usize = BUFFER_SIZE * ITER_COUNT * JOB_COUNT;


pub fn generate() -> io::Result<()> {
    let n_workers = num_cpus::get();
    let pool = ThreadPool::new(n_workers);
    let (tx, rx) = sync_channel(n_workers);

    for _ in 0..JOB_COUNT {
        let tx = tx.clone();
        pool.execute(move || {
            let mut rng = rand::thread_rng();

            let mut buffer = [0u8; BUFFER_SIZE];

            for _ in 0..ITER_COUNT {
                for i in 0..CHUNK_SIZE {
                    let value = rng.next_u64();
                    let bytes: [u8; 8] = unsafe { transmute(value.to_be()) };
                    for j in 0..8 {
                        buffer[i * 8 + j] = bytes[j];
                    }
                }

                tx.send(buffer).expect("failed to send buffer through channel.");
            }
        });
    }

    let mut ofile = File::create("./random-data.bin")?;
    ofile.set_len(TOTAL_SIZE as u64)?;
    let mut i = 0usize;

    rx.iter().take(JOB_COUNT * ITER_COUNT).for_each(|x| {
        ofile.write_all(&x).expect("write failed.");
        i += 1;
        println!("{}kB / {}kB", i * BUFFER_SIZE / (1 << 10), JOB_COUNT * ITER_COUNT * BUFFER_SIZE / (1 << 10));
    });

    Ok(())
}
