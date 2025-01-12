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
    returns: "u32"
  },
  publicKeyBytesValidate: {
    args: ["ptr", "u64"],
    returns: "u32"
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
    returns: "u32"
  },
  toPublicKeyBytes: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  isPublicKeyEqual: {
    args: ["ptr", "ptr"],
    returns: "bool"
  }
});

export const binding = lib.symbols;

export function closeBinding(): void {
  lib.close();
}
