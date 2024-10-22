pub struct MT19937 {
    mem: Vec<u32>,
    index: usize,
}

impl MT19937 {
    const W: u32 = 32;
    const N: usize = 624;
    const M: usize = 397;
    const R: u32 = 31;
    const A: u32 = 0x9908B0DF;
    const U: u32 = 11;
    const D: u32 = 0xFFFFFFFF;
    const S: u32 = 7;
    const B: u32 = 0x9D2C5680;
    const T: u32 = 15;
    const C: u32 = 0xEFC60000;
    const L: u32 = 18;
    const F: u32 = 1812433253;
    const LOWER_MASK: u32 = (1 << MT19937::R) - 1;
    const UPPER_MASK: u32 = !MT19937::LOWER_MASK;
    
    pub fn seed(seed: u32) -> Self {
        let mut mt = MT19937{ mem: vec![0u32; MT19937::N], index: MT19937::N };
        mt.mem[0] = seed;
        for i in 1..MT19937::N {
            mt.mem[i] = (i as u32).overflowing_add(
                MT19937::F.overflowing_mul(mt.mem[i-1] ^ (mt.mem[i-1] >> (MT19937::W-2))).0
            ).0;
        }
        mt
    }

    pub fn rand(&mut self) -> u32 {
        if self.index == MT19937::N {
            self.twist();
        }
        let mut y = self.mem[self.index];
        y ^= (y >> MT19937::U) & MT19937::D;
        y ^= (y << MT19937::S) & MT19937::B;
        y ^= (y << MT19937::T) & MT19937::C;
        y ^= y >> MT19937::L;
        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..MT19937::N {
            let x = (self.mem[i] & MT19937::UPPER_MASK) + 
                (self.mem[(i+1)%MT19937::N] & MT19937::LOWER_MASK);
            let mut xa = x >> 1;
            if x % 2 != 0 {
                xa ^= MT19937::A;
            }
            self.mem[i] = self.mem[(i+MT19937::M) % MT19937::N] ^ xa;
        }
        self.index = 0;
    }

    pub fn clone(mem: Vec<u32>) -> Self {
        MT19937 { mem, index: MT19937::N }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937() {
        use std::io::{BufReader, BufRead};
        use std::fs::File;

        let f = File::open(
            "C:/Programming/workspace/rust/cryptography/cryptopals/mt19937/src/test.txt")
        .expect("open the file won't fail");
        let reader = BufReader::new(f);
        let rands = reader.lines().flat_map(|l| {
            let s = l.unwrap();
            let nums = s.trim().split_ascii_whitespace()
                .map(|n| u32::from_str_radix(n, 10).unwrap())
                .collect::<Vec<u32>>();
            nums
        }).collect::<Vec<u32>>();
        
        let mut mt = MT19937::seed(1131464071);
        for i in 0..700 {
            assert_eq!(rands[i], mt.rand());
        }
    }
}
