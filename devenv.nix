{ pkgs, ... }: {
  # GTK and Qt expose their own linker flags through pkg-config. Keeping the
  # aggregate Nix linker list would exceed Linux's argument-size limit once
  # both SDKs and their propagated dependencies are present.
  enterShell = ''
    unset NIX_CFLAGS_COMPILE NIX_LDFLAGS
  '';

  packages = with pkgs; [
    cargo-xwin
    dbus
    gtk4
    libxkbcommon
    pkg-config
    qt6.qtbase
    shellcheck
    vulkan-loader
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    version = "1.94.0";
    targets = [ "x86_64-pc-windows-msvc" ];
  };

  enterTest = ''
    cargo test --workspace --all-targets --all-features
  '';
}
