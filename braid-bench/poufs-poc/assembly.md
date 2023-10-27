Note : we use AT&T Syntax => destination last.

# CPU
Laptop, i7-8750H :
Cache line size = 64 Bytes = 8x64bit
L1 = 32KiB Data, 8 Way (8x4KiB)
L2 = 256KiB, 4 Way (4x64KiB)
L3 = 9MiB, 12 Way (12x768KiB)

Desktop, Ryzen 5 5600X :
L1 = 32KiB Data, 8 Way (8x4KiB)
L2 = 512KiB, 8 Way (8x64KiB)
L3 = 32MiB, 16 Way (16x2MiB)

# Single-core Speed
## Desktop
### single thread
1 = 4.3ms 115MB/s
4 = 5.6ms 350MB/s, 5, 6, 7, ...
9 =  ~9ms 490MB/s, 13, 19, ...
21 = 19ms 550MB/s

### multi threaded best
`6*9 = 6*410MB/s = 2.4GB/s`
Cache used : 27 / 32 MB

## Laptop
### single thread
laptop build :
1 = 5.8ms, 85MB/s
4 = 8.0ms, 250MB/s
8 =  13ms, 310MB/s

desktop build :
1 = 5.2ms, 95MB/s
4 = 7.2ms, 275MB/s
8 =  12ms, 330MB/s, 12

### multi threaded best
Laptop build : `4*4 = 4*190MB/s = 760MB/s`
Desktop build : `4*4 = 4*200MB/s = 800MB/s`

Cache used : 8 / 9 MB

Note : Everything has to fit in L3 in order for the performances to be fine, which is why lower group size are better in the multithreaded scenario.

# Dependencies
1x512KiB :
=> 512/256/128/64 = 4 conflicts in L2 (ok-tier ?)
=> + 32/16/8/4 = 8 conflicts in L1 (fine ?)

# Old Assembly :

for 1 or 2 :
```
	movq	160(%rax,%rsi), %rcx
	addq	%rbx, %rdx
	rorxq	$37, %rdx, %rdx
	xorq	%rbx, %rdx
```

for 3 or 4 at a time (with native optimizations enabled) :
```
	vmovdqu	(%rax,%rsi), %ymm5
    vpaddq	%ymm0, %ymm5, %ymm0
	vpsrlq	$37, %ymm0, %ymm6
	vpsllq	$27, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm6
```

Note : no loop enrolling for 31+ (why ?)
On laptop : Same, but no loop enrolling for 8+ ?

# Old speed

Old values, results were improved since then.
On My Laptop (i7-8750H, 4.1GHz, 9MiB L3) :
- Best values : 1 = 14.1ms 35MB/s, 2/3/4..., 5 = 21.6ms 115MB/s (9), 12 = 50ms 120MB/s
- Worst values : 38+ (~35 MB/s)
On My Desktop (Ryzen 5 5600X, 4.6GHz, 32MiB L3) :
- Best values : 1 = 11.4ms 44MB/s, 2 = 12.3ms 81MB/s, 4, 5 = 20.6 120MB/s, 6, 7, 8, 9 = 27ms 165MB/s, 11, 12, 13 = 32ms 200MB/s, 17, 19, 21 = 43ms 240MB/s
- Bad values : 38+ (~35 MB/s)
- Bad values on WSL : 31+ (50~110MB/s)
