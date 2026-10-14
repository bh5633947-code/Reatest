export interface PeDebugPayloadSpec {
  readonly type: number;
  readonly characteristics?: number;
  readonly timestamp?: number;
  readonly majorVersion?: number;
  readonly minorVersion?: number;
  readonly data: Buffer;
}

const ENTRY_SIZE = 28;

const align = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

/** Hand-authored PE debug-directory bytes, independent of the production decoder. */
export const peDebugDirectoryFixture = (
  plus = false,
  payloads: readonly PeDebugPayloadSpec[] = [rsdsPayload()],
) => {
  const optionalSize = plus ? 240 : 224;
  const pe = 0x80;
  const optional = pe + 24;
  const sectionTable = optional + optionalSize;
  const headerSize = 0x400;
  const directoryRva = 0x2000;
  const payloadStart = payloads.length * ENTRY_SIZE;
  let payloadCursor = payloadStart;
  const payloadOffsets: number[] = [];
  for (const payload of payloads) {
    payloadOffsets.push(payloadCursor);
    payloadCursor += payload.data.length;
  }
  const used = payloadCursor;
  const rawSize = Math.max(512, align(used, 512));
  const bytes = Buffer.alloc(headerSize + rawSize);
  bytes.writeUInt16LE(0x5a4d, 0);
  bytes.writeUInt32LE(pe, 60);
  bytes.writeUInt32LE(0x4550, pe);
  bytes.writeUInt16LE(plus ? 0x8664 : 0x14c, pe + 4);
  bytes.writeUInt16LE(1, pe + 6);
  bytes.writeUInt16LE(optionalSize, pe + 20);
  bytes.writeUInt16LE(plus ? 0x20b : 0x10b, optional);
  bytes.writeUInt32LE(headerSize, optional + 60);
  bytes.writeUInt32LE(16, optional + (plus ? 108 : 92));
  const debugDirectoryAt = optional + (plus ? 112 : 96) + 6 * 8;
  const directoryFile = headerSize;
  if (payloads.length > 0) {
    bytes.writeUInt32LE(directoryRva, debugDirectoryAt);
    bytes.writeUInt32LE(payloads.length * ENTRY_SIZE, debugDirectoryAt + 4);
  }
  bytes.write(".rdata", sectionTable, "ascii");
  bytes.writeUInt32LE(used, sectionTable + 8);
  bytes.writeUInt32LE(directoryRva, sectionTable + 12);
  bytes.writeUInt32LE(rawSize, sectionTable + 16);
  bytes.writeUInt32LE(headerSize, sectionTable + 20);
  payloads.forEach((payload, index) => {
    const entry = directoryFile + index * ENTRY_SIZE;
    const dataOffset = directoryFile + (payloadOffsets[index] ?? 0);
    bytes.writeUInt32LE(payload.characteristics ?? 0, entry);
    bytes.writeUInt32LE(payload.timestamp ?? 0, entry + 4);
    bytes.writeUInt16LE(payload.majorVersion ?? 0, entry + 8);
    bytes.writeUInt16LE(payload.minorVersion ?? 0, entry + 10);
    bytes.writeUInt32LE(payload.type, entry + 12);
    bytes.writeUInt32LE(payload.data.length, entry + 16);
    bytes.writeUInt32LE(
      directoryRva + (payloadOffsets[index] ?? 0),
      entry + 20,
    );
    bytes.writeUInt32LE(dataOffset, entry + 24);
    payload.data.copy(bytes, dataOffset);
  });
  return {
    bytes,
    debugDirectoryAt,
    sectionAt: sectionTable,
    entryOffsets: payloads.map(
      (_, index) => directoryFile + index * ENTRY_SIZE,
    ),
    payloadOffsets: payloadOffsets.map((offset) => directoryFile + offset),
  };
};

/** RSDS CodeView record with a known GUID, age, and PDB path. */
export const rsdsPayload = (
  pdbPath = "C:\\build\\sample.pdb",
  guid = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex"),
  age = 7,
): PeDebugPayloadSpec => {
  const path = Buffer.from(`${pdbPath}\0`, "utf8");
  const data = Buffer.alloc(24 + path.length);
  data.write("RSDS", 0, "ascii");
  guid.copy(data, 4);
  data.writeUInt32LE(age, 20);
  path.copy(data, 24);
  return { type: 2, data };
};

/** NB10 CodeView record with a PDB path and age. */
export const nb10Payload = (
  pdbPath = "sample.pdb",
  age = 3,
): PeDebugPayloadSpec => {
  const path = Buffer.from(`${pdbPath}\0`, "utf8");
  const data = Buffer.alloc(16 + path.length);
  data.write("NB10", 0, "ascii");
  data.writeUInt32LE(age, 12);
  path.copy(data, 16);
  return { type: 2, data };
};

/** IMAGE_DEBUG_TYPE_REPRO payload whose bytes are the deterministic hash. */
export const reproPayload = (
  hash = Buffer.from("0123456789abcdef0123456789abcdef", "hex"),
): PeDebugPayloadSpec => ({ type: 16, data: hash });

/** IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS payload. */
export const exDllCharacteristicsPayload = (
  characteristics = 0x1000,
): PeDebugPayloadSpec => {
  const data = Buffer.alloc(4);
  data.writeUInt32LE(characteristics, 0);
  return { type: 20, data };
};
