import {binding} from "./binding.ts";
import { BLST_SUCCESS, PUBLIC_KEY_LENGTH_COMPRESSED, PUBLIC_KEY_LENGTH_UNCOMPRESSED } from "./const.ts";
import { fromHex, toError, toHex } from "./util.ts";

export class PublicKey {
  private blst_point: Uint8Array;
  private constructor(buffer: Uint8Array) {
    this.blst_point = buffer;
  }

  /**
   * Called from SecretKey so that we keep the constructor private.
   */
  public static fromSecretKey(sk: Uint8Array): PublicKey {
    const buffer = new Uint8Array(PUBLIC_KEY_LENGTH_UNCOMPRESSED);
    binding.secretKeyToPublicKey(buffer, sk);
    return new PublicKey(buffer);
  }

  /**
   * Deserialize a public key from a byte array.
   *
   * If `pk_validate` is `true`, the public key will be infinity and group checked.
   */
  public static fromBytes(bytes: Uint8Array, pkValidate?: boolean | undefined | null): PublicKey {
    const buffer = new Uint8Array(PUBLIC_KEY_LENGTH_UNCOMPRESSED);
    let res = binding.deserializePublicKey(buffer, bytes, bytes.length);
    if (res !== BLST_SUCCESS) {
      throw toError(res);
    }

    if (pkValidate) {
      res = binding.validatePublicKey(buffer);
      if (res !== BLST_SUCCESS) {
        throw toError(res);
      }
    }
    return new PublicKey(buffer);
  }

  /**
   * Deserialize a public key from a hex string.
   *
   * If `pk_validate` is `true`, the public key will be infinity and group checked.
   */
  static fromHex(hex: string, pkValidate?: boolean | undefined | null): PublicKey {
    const bytes = fromHex(hex);
    return PublicKey.fromBytes(bytes, pkValidate);
  }

  /** Serialize a public key to a byte array. */
  public toBytes(inCompress?: boolean| undefined | null): Uint8Array {
    // this is the same to Rust binding
    const compress = inCompress ?? true;
    if (compress) {
      const out = new Uint8Array(PUBLIC_KEY_LENGTH_COMPRESSED);
      binding.compressPublicKey(out, this.blst_point);
      return out;
    }

    const out = new Uint8Array(PUBLIC_KEY_LENGTH_UNCOMPRESSED);
    binding.serializePublicKey(out, this.blst_point);
    return out;
  }

  /** Serialize a public key to a hex string. */
  public toHex(compress?: boolean | undefined | null): string {
    const bytes = this.toBytes(compress);
    return toHex(bytes);
  }

  /** Validate a public key with infinity and group check. */
  public keyValidate(): void {
    const res = binding.validatePublicKey(this.blst_point);
    if (res !== BLST_SUCCESS) {
      throw toError(res);
    }
  }
}