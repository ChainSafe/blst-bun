import {dlopen} from "bun:ffi";

const path = "lib/libblst_min_pk.dylib";

// Load the compiled Zig shared library
const lib = dlopen(path, {
  // PublicKey functions
  defaultPublicKey: {
      args: ["ptr"],
      returns: "void"
  },
  validatePublicKey: {
    args: ["ptr"],
    returns: "u8"
  },
  publicKeyBytesValidate: {
    args: ["ptr", "u64"],
    returns: "u8"
  },
  publicKeyFromAggregate: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  compressPublicKey: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  serializePublicKey: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  uncompressPublicKey: {
    args: ["ptr", "ptr", "u64"],
    returns: "void"
  },
  deserializePublicKey: {
    args: ["ptr", "ptr", "u64"],
    returns: "u8"
  },
  toPublicKeyBytes: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  isPublicKeyEqual: {
    args: ["ptr", "ptr"],
    returns: "bool"
  },
  // SecretKey functions
  defaultSecretKey: {
    args: ["ptr"],
    returns: "void"
  },
  secretKeyGen: {
    args: ["ptr", "ptr", "u32", "ptr", "u32"],
    returns: "u8",
  },
  secretKeyDeriveMasterEip2333: {
    args: ["ptr", "ptr", "u32"],
    returns: "u8",
  },
  secretKeyDeriveChildEip2333: {
    args: ["ptr", "ptr", "u32"],
    returns: "void",
  },
  secretKeyFromBytes: {
    args: ["ptr", "ptr", "u32"],
    returns: "u8",
  },
  secretKeyToBytes: {
    args: ["ptr", "ptr"],
    returns: "void",
  },
  secretKeyToPublicKey: {
    args: ["ptr", "ptr"],
    returns: "void",
  },
});

export const binding = lib.symbols;

export function closeBinding(): void {
  lib.close();
}
