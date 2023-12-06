/// Given an index representing the depth of a node in the Merkle Patricia Tree, returns true if the bit is 1,
/// false if the bit is 0 (the array of u8 contains 256 total bits).
pub fn get_bit_direction(arr: &[u8; 32], index: u8) -> bool {
    let byte = arr[(index / 8) as usize];
    let sub_index: u8 = 1 << (7 - (index % 8));
    (byte & sub_index) > 0
}
