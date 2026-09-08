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
    llvmPackages.llvm
    nasm
    pkg-config
    qt6.qtbase
    shellcheck
    vulkan-loader
    # Native resource scripts in dependencies also need a compiler during xwin checks.
    (writeShellScriptBin "rc.exe" ''
      exec ${llvmPackages.llvm}/bin/llvm-rc "$@"
    '')
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
