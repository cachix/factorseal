{ pkgs, ... }: {
  packages = with pkgs; [
    cargo
    clippy
    dbus
    pkg-config
    pcsclite
    rustc
    rustfmt
    shellcheck
    tpm2-tss
  ];

  enterTest = ''
    cargo test --all-features
  '';
}
