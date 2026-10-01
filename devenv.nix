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
    # cargo-xwin's MSVC cross-linking needs llvm-ar/llvm-lib/llvm-rc, which
    # it expects to already be on PATH rather than fetching itself.
    llvmPackages_21.bintools-unwrapped
    # turso_sdk_kit's build script shells out to a literal `rc.exe` on PATH
    # to compile a Windows version resource; there's no MSVC rc.exe here, so
    # stand one in with llvm-rc. It needs a plain clang to preprocess the
    # generated .rc (it uses #define macros); the nix cc-wrapper injects
    # -fPIC unconditionally, which clang rejects for the msvc target, so
    # point it at the unwrapped clang instead.
    (writeShellScriptBin "rc.exe" ''
      export PATH="${llvmPackages_21.clang-unwrapped}/bin:$PATH"
      exec ${llvmPackages_21.bintools-unwrapped}/bin/llvm-rc "$@"
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
