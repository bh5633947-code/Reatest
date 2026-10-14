import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseCodeViewData } from "../../domain/binaryTarget.js";
import {
  inspectPeDebugDirectoryInputSchema,
  peDebugDirectorySchema,
} from "../../domain/native/peDebugDirectory.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  exDllCharacteristicsPayload,
  nb10Payload,
  peDebugDirectoryFixture,
  reproPayload,
  rsdsPayload,
} from "./PeDebugDirectory.fixture.js";
import { parsePeDebugDirectory } from "./PeDebugDirectoryParser.js";

const parse = (bytes: Buffer, maxEntries = 256) =>
  parsePeDebugDirectory(
    bytes,
    {
      path: "/fixtures/sample.exe",
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    },
    inspectPeDebugDirectoryInputSchema.parse({
      path: "/fixtures/sample.exe",
      max_entries: maxEntries,
    }),
  );

describe("portable PE debug-directory parsing", () => {
  it.each([false, true])(
    "preserves RSDS path, GUID, age and payload hash (PE32+ = %s)",
    (plus) => {
      const payload = rsdsPayload();
      const { bytes } = peDebugDirectoryFixture(plus, [payload]);
      const result = peDebugDirectorySchema.parse(parse(bytes));
      const expected = parseCodeViewData(payload.data, payload.data.length);
      expect(result.format).toBe(plus ? "pe32-plus" : "pe32");
      expect(result.coverage).toEqual({ status: "complete", entries: 1 });
      expect(result.entries[0]).toMatchObject({
        type: 2,
        type_name: "codeview",
        payload: {
          sha256: createHash("sha256").update(payload.data).digest("hex"),
          decoded: {
            kind: "codeview_rsds",
            pdb_path: expected?.pdbPath,
            pdb_file_name: expected?.pdbFileName,
            guid: expected?.guid,
            age: expected?.age,
          },
        },
      });
    },
  );

  it("preserves NB10, REPRO and EX_DLLCHARACTERISTICS payloads in directory order", () => {
    const payloads = [
      nb10Payload("legacy.pdb", 4),
      reproPayload(),
      exDllCharacteristicsPayload(0x1000),
    ];
    const { bytes } = peDebugDirectoryFixture(false, payloads);
    const result = peDebugDirectorySchema.parse(parse(bytes));
    expect(result.entries.map((entry) => entry.payload.decoded)).toEqual([
      {
        kind: "codeview_nb10",
        pdb_path: "legacy.pdb",
        pdb_file_name: "legacy.pdb",
        age: 4,
      },
      {
        kind: "repro",
        hash_hex: payloads[1]!.data.toString("hex"),
      },
      { kind: "ex_dllcharacteristics", characteristics: 0x1000 },
    ]);
  });

  it("returns an empty complete inventory when the debug directory is absent", () => {
    const { bytes } = peDebugDirectoryFixture(false, []);
    const result = peDebugDirectorySchema.parse(parse(bytes));
    expect(result.directory).toBeNull();
    expect(result.entries).toEqual([]);
    expect(result.limitations.join("\n")).toContain(
      "Absence does not prove the image was built without debug information",
    );
  });

  it("fails without a partial inventory when the entry budget is exceeded", () => {
    const { bytes } = peDebugDirectoryFixture(false, [
      rsdsPayload(),
      reproPayload(),
    ]);
    expect(() => parse(bytes, 1)).toThrow(ArtifactReaderFailure);
    try {
      parse(bytes, 1);
    } catch (cause) {
      expect(cause).toMatchObject({
        reason: "limit",
        message: expect.stringContaining("entry budget"),
      });
    }
  });

  it("fails when the debug directory size is not a multiple of 28", () => {
    const fixture = peDebugDirectoryFixture();
    fixture.bytes.writeUInt32LE(27, fixture.debugDirectoryAt + 4);
    expect(() => parse(fixture.bytes)).toThrow(/not a multiple of 28/u);
  });
});
