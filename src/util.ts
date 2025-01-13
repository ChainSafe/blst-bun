
export function toHex(buffer: Uint8Array | Parameters<typeof Buffer.from>[0]): string {
  if (Buffer.isBuffer(buffer)) {
    return "0x" + buffer.toString("hex");
  } else if (buffer instanceof Uint8Array) {
    return "0x" + Buffer.from(buffer.buffer, buffer.byteOffset, buffer.length).toString("hex");
  } else {
    return "0x" + Buffer.from(buffer).toString("hex");
  }
}

export function fromHex(hex: string): Uint8Array {
  const b = Buffer.from(hex.replace("0x", ""), "hex");
  return new Uint8Array(b.buffer, b.byteOffset, b.length);
}

export function blstErrorToReason(error: number): string {
  switch (error) {
    case 0:
      return "BLST_SUCCESS";
    case 1:
      return "Invalid encoding";
    case 2:
      return "Point not on curve";
    case 3:
      return "Point not in group";
    case 4:
      return "Aggregation type mismatch";
    case 5:
      return "Verification failed";
    case 6:
      return "Public key is infinity";
    case 7:
      return "Invalid scalar";
    default:
      return `Unknown error code ${error}`;
  }
}