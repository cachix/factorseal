{ pkgs, ... }: {
  packages = with pkgs; [
    cargo
    clippy
    dbus
    pkg-config
    pcsclite
    rustc
    rustfmt
    tpm2-tss
  ];

  enterTest = ''
    cargo test --all-features
  '';
}
