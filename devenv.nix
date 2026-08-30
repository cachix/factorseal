{ pkgs, ... }: {
  packages = with pkgs; [
    cargo-xwin
    dbus
    pkg-config
    shellcheck
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    version = "1.91.0";
    targets = [ "x86_64-pc-windows-msvc" ];
  };

  enterTest = ''
    cargo test --workspace --all-targets --all-features
  '';
}
