{
  description = "A WireGuard interface status display tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "wg-show";
          version = "1.0.8";

          src = ./.;

          vendorHash = "sha256-/Gsqc8rEptMBItqeb/N/gE4V3iUGZa8k1GqUR1+togY=";

          ldflags = [ "-s" "-w" ];

          meta = with pkgs.lib; {
            description = "A WireGuard interface status display tool";
            homepage = "https://github.com/bdim404/wg-show";
            license = licenses.gpl3Only;
            maintainers = [ ];
            mainProgram = "wg-show";
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/wg-show";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            wireguard-tools
          ];
        };
      }
    );
}
