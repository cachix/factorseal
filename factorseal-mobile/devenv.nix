{ pkgs, lib, config, ... }: {
  android = {
    enable = true;
    platforms.version = [ "36" "37.1" ];
    buildTools.version = [ "36.0.0" ];
    ndk.version = [ "28.2.13676358" ];
    cmake.version = [ ];
    systemImageTypes = [ "google_apis" ];
    abis = [ "x86_64" ];
    googleTVAddOns.enable = false;
    extras = [ ];
  };

  languages.java.jdk.package = pkgs.jdk21;

  languages.rust = {
    enable = true;
    channel = "stable";
    version = "1.99.0";
    targets = [
      "aarch64-linux-android"
      "armv7-linux-androideabi"
      "x86_64-linux-android"
      "aarch64-apple-ios"
      "aarch64-apple-ios-sim"
    ];
  };

  packages = with pkgs; [
    cargo-ndk
    ktlint
    librsvg
    python3
  ];

  enterShell = lib.mkAfter ''
    if [ -f local.properties ]; then sed -i '/^ndk.dir=/d' local.properties; fi
  '';

  scripts.android-emulator.exec = ''
    if ! avdmanager list avd -c | grep -qx factorseal; then
      echo no | avdmanager create avd --name factorseal --package "system-images;android-36;google_apis;x86_64"
    fi
    env -u LD_LIBRARY_PATH emulator -avd factorseal "$@"
  '';

  env.GRADLE_USER_HOME = "${config.devenv.state}/gradle";
  env.KONAN_DATA_DIR = "${config.devenv.state}/konan";
}
