{
  description = "Base flake for citadel";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      with pkgs;
      {
        devShells.default = mkShell {
          buildInputs = [
            rust-bin.stable.latest.default
            pkg-config
            udev
            libclang.lib
            sccache

          ];
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          RUSTC_WRAPPER="${pkgs.sccache}/bin/sccache";

          shellHook = ''
            echo "in rust dev shell";
          '';
        };
      }
    );
}

