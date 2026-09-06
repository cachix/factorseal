fn main() {
    let root = std::path::PathBuf::from(std::env::args_os().nth(1).expect("corpus directory"));
    for name in [
        "metadata",
        "protocol",
        "document",
        "history",
        "envelope",
        "commit_chain",
        "secret_service",
        "archive",
        "transfer",
        "bootstrap",
    ] {
        let directory = root.join(name);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("empty-object"), b"{}").unwrap();
        std::fs::write(directory.join("invalid"), [0xff, 0, 1, 127]).unwrap();
    }
    for (index, (name, bytes)) in factorseal::fuzzing::seeds().into_iter().enumerate() {
        std::fs::write(root.join(name).join(format!("valid-{index}")), bytes).unwrap();
    }
}
