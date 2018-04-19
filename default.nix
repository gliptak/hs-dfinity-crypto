{ pkgs ? import <nixpkgs> {} }:
  with pkgs;
  let
    math = import ../bn/bn.nix
    {
      inherit clang gnumake gmpxx llvm openssl;
      stdenv = clangStdenv;
    };
    crypto = haskellPackages.callCabal2nix "dfinity-crypto" ./. {
      bls384 = math;
      mcl = math;
    };
  in
  if pkgs.lib.inNixShell 
  then stdenv.lib.overrideDerivation crypto.env (
    oldAttrs: {
      nativeBuildInputs = oldAttrs.nativeBuildInputs ++ [ cabal-install stack ];
    }
  )
  else crypto
