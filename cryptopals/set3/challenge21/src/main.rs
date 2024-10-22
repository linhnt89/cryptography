use mt19937;

fn main() {
    let mut mt = mt19937::MT19937::seed(1131464071);
    println!("{}", mt.rand());
}

