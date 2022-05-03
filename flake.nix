{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crate2nix = {
      url = "github:kolloch/crate2nix";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    crate2nix,
    ...
  }: let
    system = "x86_64-linux";
    overlays = [
      rust-overlay.overlay
      (self: super: {
        rustc = self.rust-bin.stable.latest.default;
        cargo = self.rust-bin.stable.latest.default;
      })
    ];
    pkgs = import nixpkgs {
      inherit system overlays;
    };

    inherit
      (import "${crate2nix}/tools.nix" {inherit pkgs;})
      generatedCargoNix
      ;

    name = "jdns";
    natty =
      (
        import
        (generatedCargoNix {
          inherit name;
          src = ./.;
        })
        {inherit pkgs;}
      )
      .rootCrate
      .build;

    nativeBuildInputs = with pkgs; [
      rustc

      cargo
      cargo-edit
      cargo-audit
      cargo-tarpaulin
      clippy
    ];
  in
    with pkgs; {
      packages.${system} = {
        natty = natty;
        default = natty;
      };
      devShells.${system}.default = mkShell {
        inherit nativeBuildInputs;
      };
    };
}
