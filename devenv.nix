{ pkgs, ... }: {
  # GTK and Qt expose their own linker flags through pkg-config. Keeping the
  # aggregate Nix linker list would exceed Linux's argument-size limit once
  # both SDKs and their propagated dependencies are present.
  enterShell = ''
    unset NIX_CFLAGS_COMPILE NIX_LDFLAGS
  '';

  packages = with pkgs; [
    nodejs
    cargo-xwin
    dbus # dbus-run-session for integration tests; Rust uses zbus.
    gtk4
    libxkbcommon
    pkg-config
    python3
    qt6.qtbase
    shellcheck
    vulkan-loader
    yyjson # Upstream SecretSpec IPC conformance runner's C transport fixtures.
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    version = "1.97.1";
    targets = [ "x86_64-pc-windows-msvc" ];
  };

  enterTest = ''
    bash scripts/test-with-dbus.sh cargo test --workspace --all-targets --all-features
  '';
}
