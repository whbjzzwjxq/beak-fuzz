fn main() {
    if let Err(err) = beak_sp1_fb38df2c::backend::run_cli() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
