fn main() {
    if factorseal::isolation::parser::run().is_err() {
        // Never print attacker-controlled parser diagnostics or secret data.
        std::process::exit(1);
    }
}
