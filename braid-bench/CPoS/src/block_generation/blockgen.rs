use std::vec::Vec;

pub const E: usize = 16;
pub const D: usize = E + 1; // Amount of dependencies of each fragment
pub const N: usize = 1 << E as usize; // Amount of fragment per block
const INDEX_MASK: usize = N - 1;

pub const ABSOLUTE_SPEEDUP_UPPERBOUND: usize = E*(1 << (E - 1))*E + (N/2) - 1;
const DESIRED_SPEEDUP_RATIO: usize = 2;
const STEPS_LOWERBOUND: usize = DESIRED_SPEEDUP_RATIO * ABSOLUTE_SPEEDUP_UPPERBOUND;
pub const SIZE: usize = (STEPS_LOWERBOUND + (E - 1)) / E;
// pub const STEPS: usize = SIZE * E;

pub type FRAGMENT = u64;
pub const BLOCK_BYTE_SIZE: usize = N * 8;

pub const GROUP_SIZE: usize = 4;
pub const GROUP_BYTE_SIZE: usize = BLOCK_BYTE_SIZE * GROUP_SIZE;
pub type FragmentGroup = [FRAGMENT; GROUP_SIZE];
// pub type Block = [Fragment; N as usize];
pub type BlockGroup = Vec<FragmentGroup>;

pub const INIT_SIZE_EXP: usize = 2;
pub const INIT_SIZE: usize = 1 << INIT_SIZE_EXP; // 4x64bit = 256bit
pub const INIT_MASK: usize = INIT_SIZE - 1;
pub type InitGroup = [FragmentGroup; INIT_SIZE];

pub fn block_gen(inits: InitGroup) -> BlockGroup {
    if is_x86_feature_detected!("avx2") {
        unsafe { block_gen_avx2(inits) }
    } else {
        block_gen_inner(inits)
    }
}

#[target_feature(enable = "avx2")]
unsafe fn block_gen_avx2(inits: InitGroup) -> BlockGroup {
    block_gen_inner(inits)
}

#[inline(always)]
fn block_gen_inner(inits: InitGroup) -> BlockGroup {
    // let mut block: Block = [[0; FRAGMENTSIZE]; N as usize];
    let mut block: BlockGroup = vec![[0; GROUP_SIZE]; N as usize];
    
    let start = N - (SIZE % N);

    let mut from = 0;
    let mut last: FragmentGroup = inits[0];
    for k in 0..D {
        let to = 1 << k;
        for i in from..to {
            // let index = (i + start) % N;
            let index = (i + start) & INDEX_MASK;
            let init = inits[(i + start) & INIT_MASK];
            let mut next_fragment = last;
            for j in 1..k {
                let jump = 1 << j;
                // let target = (index + N - jump) % N;
                let target = (index + N - jump) & INDEX_MASK;
                let x = block[target];
                if (j & 1) == 1 {
                    next_fragment = add(next_fragment, x);
                } else {
                    next_fragment = xor(next_fragment, x);
                }
            }
            for j in k..D {
                if (j & 1) == 1 {
                    next_fragment = add(next_fragment, init);
                } else {
                    next_fragment = xor(next_fragment, init);
                }
            }
            last = rot(next_fragment);
            block[index] = last;
        }
        from = to;
    }
    for i in N..SIZE {
        let index = (i + start) % N;
        let mut next_fragment = last;
        for j in 1..D {
            let jump = 1 << j;
            // let target = (index + N - jump) % N;
            let target = (index + N - jump) & INDEX_MASK;
            let x = block[target];
            if (j & 1) == 1 {
                next_fragment = add(next_fragment, x);
            } else {
                next_fragment = xor(next_fragment, x);
            }
        }
        last = rot(next_fragment);
        block[index] = last;
    }
    return block;
}

#[inline(always)]
fn add(a: FragmentGroup, b: FragmentGroup) -> FragmentGroup {
    let mut c: FragmentGroup = [0; GROUP_SIZE];
    for i in 0..GROUP_SIZE {
        c[i] = a[i].wrapping_add(b[i]);
    }
    return c
}

#[inline(always)]
fn xor(a: FragmentGroup, b: FragmentGroup) -> FragmentGroup {
    let mut c: FragmentGroup = [0; GROUP_SIZE];
    for i in 0..GROUP_SIZE {
        c[i] = a[i] ^ b[i];
    }
    return c
}

#[inline(always)]
fn rot(a: FragmentGroup) -> FragmentGroup {
    let mut b: FragmentGroup = [0; GROUP_SIZE];
    for i in 0..GROUP_SIZE {
        b[i] = a[i].rotate_left(19); // Recommended shifts : 11/19/27
    }
    return b;
}