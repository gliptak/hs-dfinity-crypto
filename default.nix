{ pkgs ? import <nixpkgs> {} }:
    with pkgs;
    let crypto = haskellPackages.callCabal2nix "dfinity-crypto" ./. {};
    if pkgs.lib.inNixShell 
    then stdenv.lib.overrideDerivation crypto.env (oldAttrs: {
        nativeBuildInputs = oldAttrs.nativeBuildInputs ++ [ cabal-install stack ];
    })
    else crypto;
