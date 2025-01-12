import { test, expect, afterAll } from "bun:test";
import { BLST_PK_IS_INFINITY, BLST_POINT_NOT_ON_CURVE, PUBLIC_KEY_SIZE } from "../../src/const";
import { closeLib, lib } from "../../src/binding";

test("load binding", () => {
  const buffer = new Uint8Array(PUBLIC_KEY_SIZE).fill(1);
  lib.symbols.defaultPublicKey(buffer);
  let validationRes = lib.symbols.validatePublicKey(buffer);
  expect(validationRes).toBe(BLST_PK_IS_INFINITY);
  validationRes = lib.symbols.publicKeyBytesValidate(buffer, PUBLIC_KEY_SIZE);
  expect(validationRes).toBe(BLST_POINT_NOT_ON_CURVE);

  // 0ae7e5822ba97ab07877ea318e747499da648b27302414f9d0b9bb7e3646d248be90c9fdaddfdb93485a6e9334f0109301f36856007e1bc875ab1b00dbf47f9ead16c5562d889d8b270002ade81e78d473204fcb51ede8659bce3d95c67903bc
  const sampleBlsPubKey = new Uint8Array([
    10, 231, 229, 130,  43, 169, 122, 176,
    120, 119, 234,  49, 142, 116, 116, 153,
    218, 100, 139,  39,  48,  36,  20, 249,
    208, 185, 187, 126,  54,  70, 210,  72,
    190, 144, 201, 253, 173, 223, 219, 147,
    72,  90, 110, 147,  52, 240,  16, 147,
    1, 243, 104,  86,   0, 126,  27, 200,
    117, 171,  27,   0, 219, 244, 127, 158,
    173,  22, 197,  86,  45, 136, 157, 139,
    39,   0,   2, 173, 232,  30, 120, 212,
    115,  32,  79, 203,  81, 237, 232, 101,
    155, 206,  61, 149, 198, 121,   3, 188
  ]);

  // this buffer is the result, it's just the place holder for pk_aff_type
  // we can use it as data for a PublicKey class, to be modelled later
  const deserializeResult = lib.symbols.deserializePublicKey(buffer, sampleBlsPubKey, sampleBlsPubKey.length);
  expect(deserializeResult).toBe(0);

  validationRes = lib.symbols.validatePublicKey(buffer);
  expect(validationRes).toBe(0);
});

afterAll(() => {
  closeLib();
})