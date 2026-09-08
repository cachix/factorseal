fn main() {
    if factorseal::isolation::network::run().is_err() {
        std::process::exit(1);
    }
}
