# Proof of Efficiently Usable Space (PoEUS):
The project aims to provide a complete end-to-end implementation of the PoEUS protocol. 
The program is simply executed by running: <br>
```cargo run --release -- <logging option>``` <br> 
where the logging option can be *error*, *warn*, *info*, *debug* or *trace* (Note that, because the program is executed in one machine, the more the logs displayed on the screen, the more time it may take for the execution of the protocol). The suggested execution is: <br>
```cargo run --release -- info``` <br>
Although the maximum tested size was *3.6 Gb*, it is possible to substitute the *input.mp4* file with any other of arbitrary size.
To ensure that the parallelization of the device is active (most of the time it is by default), add `RUSTFLAGS='-C target-cpu=native'`. This will allow to make computations in parallel in the block generation function.
