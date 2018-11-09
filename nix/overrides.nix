{ pkgs }:

self: super:

with { inherit (pkgs.stdenv) lib; };

with pkgs.haskell.lib;

{
  azure-email = (
    with rec {
      azure-emailSource = pkgs.lib.cleanSource ../.;
      azure-emailBasic = self.callCabal2nix "azure-email" azure-emailSource {};
    };
    overrideCabal azure-emailBasic (old: {
    })
  );
}
