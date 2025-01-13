import { describe, it, test, expect, afterAll } from "bun:test";
import { closeBinding } from "../../src/binding";
import { PublicKey } from "../../src/publicKey";
import { expectEqualHex } from "../utils/helpers";
import { validPublicKey } from "../__fixtures__";

describe("PublicKey", () => {
  it("should exist", () => {
    expect(PublicKey).toBeFunction();
  });

  describe("constructors", () => {
    // no need "should have a private constructor"

    describe("deserialize", () => {
      it("should only take 48 or 96 bytes", () => {
        expect(() => PublicKey.fromBytes(Buffer.alloc(32, "*"))).toThrow("Invalid encoding");
      });

      it("should take uncompressed byte arrays", () => {
        expectEqualHex(PublicKey.fromBytes(validPublicKey.uncompressed).toBytes(), validPublicKey.compressed);
      });
    });
  });


});

afterAll(() => {
  closeBinding();
})