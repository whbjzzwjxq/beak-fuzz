fn main() {
    if let Err(err) = beak_sp1_3561f006::backend::run_cli() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
