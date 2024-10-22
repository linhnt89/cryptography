use mt19937;
use rand::{thread_rng, Rng};

fn main() {
    let mut mt = mt19937::MT19937::seed(thread_rng().gen());
    let states = (0..624).into_iter().map(|_| {
        get_internal_state(mt.rand())
    }).collect::<Vec<u32>>();
    let mut mt_clone = mt19937::MT19937::clone(states);
    for _ in 0..624 {
        assert_eq!(mt.rand(), mt_clone.rand());
    }
}

fn get_internal_state(num: u32) -> u32 {
    const U: u32 = 11;
    const D: u32 = 0xFFFFFFFF;
    const S: u32 = 7;
    const B: u32 = 0x9D2C5680;
    const T: u32 = 15;
    const C: u32 = 0xEFC60000;
    const L: u32 = 18;
    
    let mut state = num;
    state = reverse(state, L, D, false);
    state = reverse(state, T, C, true);
    state = reverse(state, S, B, true);
    state = reverse(state, U, D, false);
    state
}

fn reverse(num: u32, bits_shift: u32, fval: u32, is_left: bool) -> u32 {
    let mut turn = 1;
    let mut reverse_num = num;
    if bits_shift < 32/2 {
        turn += 32 - bits_shift;
    }
    for _ in 0..turn {
        if is_left {
            reverse_num = num ^ ((reverse_num << bits_shift) & fval);
        } else {
            reverse_num = num ^ ((reverse_num >> bits_shift) & fval); 
        }
    }
    reverse_num
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse() {
        let x = 10u32;
        let y = x ^ (x >> 18);
        assert_eq!(x, reverse(y, 18, 0, false));
        let y = x ^ (x >> 11);
        assert_eq!(x, reverse(y, 11, 0, false));
        let y = x ^ ((x << 18) & 0xABC10343);
        assert_eq!(x, reverse(y, 18, 0xABC10343, true));
        let y = x ^ ((x << 11) & 0xABC10343);
        assert_eq!(x, reverse(y, 11, 0xABC10343, true));
    }

    #[test]
    fn test_get_internal_state() {
        let mut mt = mt19937::MT19937::seed(1131464071);
        let num = mt.rand();
        assert_eq!(1065953061, get_internal_state(num));
    }
}