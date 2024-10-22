use std::{thread, time::{self, SystemTime, UNIX_EPOCH}};
use mt19937;
use rand::{thread_rng, Rng};

fn main() {
    let rand_num = routine();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    for i in 40u32..1000u32 {
        let mut mt = mt19937::MT19937::seed(now-i);
        if rand_num == mt.rand() {
            println!("The seed is {}", now-i)
        }
    }
}

fn routine() -> u32 {
    thread::sleep(time::Duration::from_secs(thread_rng().gen_range(40..=1000)));
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut mt = mt19937::MT19937::seed(t.as_secs() as u32);
    thread::sleep(time::Duration::from_secs(thread_rng().gen_range(40..=1000)));
    mt.rand()
}