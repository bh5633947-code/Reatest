import { describe, expect, it } from "vitest";
import {
  inspectPeDebugDirectoryInputSchema,
  peDebugDirectorySchema,
  peDebugTypeName,
} from "./peDebugDirectory.js";

describe("peDebugTypeName", () => {
  it("names documented IMAGE_DEBUG_TYPE values and leaves others as other", () => {
    expect(peDebugTypeName(2)).toBe("codeview");
    expect(peDebugTypeName(16)).toBe("repro");
    expect(peDebugTypeName(20)).toBe("ex_dllcharacteristics");
    expect(peDebugTypeName(99)).toBe("other");
  });
});

describe("inspectPeDebugDirectoryInputSchema", () => {
  it("rejects unknown fields and non-positive entry budgets", () => {
    expect(
      inspectPeDebugDirectoryInputSchema.safeParse({
        path: "/artifacts/a.exe",
        extra: true,
      }).success,
    ).toBe(false);
    expect(
      inspectPeDebugDirectoryInputSchema.safeParse({
        path: "/artifacts/a.exe",
        max_entries: 0,
      }).success,
    ).toBe(false);
  });

  it("defaults file and entry budgets", () => {
    expect(
      inspectPeDebugDirectoryInputSchema.parse({ path: "/artifacts/a.exe" }),
    ).toMatchObject({
      max_file_bytes: 67108864,
      max_entries: 256,
    });
  });
});

describe("peDebugDirectorySchema", () => {
  const report = {
    artifact: {
      path: "/artifacts/a.exe",
      sha256: "a".repeat(64),
      bytes: 128,
    },
    format: "pe32" as const,
    machine: 0x14c,
    directory: {
      rva: 0x2000,
      location: { offset: 64, bytes: 28 },
      data_directory_location: { offset: 8, bytes: 8 },
    },
    entries: [
      {
        index: 0,
        type: 16,
        type_name: "repro" as const,
        characteristics: 0,
        timestamp: 0,
        major_version: 0,
        minor_version: 0,
        directory_location: { offset: 64, bytes: 28 },
        address_of_raw_data: 0x2000,
        pointer_to_raw_data: 92,
        payload: {
          location: { offset: 92, bytes: 4 },
          sha256: "b".repeat(64),
          decoded: { kind: "repro" as const, hash_hex: "abcd" },
        },
      },
    ],
    coverage: { status: "complete" as const, entries: 1 },
    limitations: ["static inventory"],
  };

  it("rejects coverage that disagrees with retained entries", () => {
    expect(
      peDebugDirectorySchema.safeParse({
        ...report,
        coverage: { status: "complete", entries: 9 },
      }).success,
    ).toBe(false);
  });

  it("rejects a payload that leaves the artifact", () => {
    expect(
      peDebugDirectorySchema.safeParse({
        ...report,
        entries: [
          {
            ...report.entries[0]!,
            payload: {
              ...report.entries[0]!.payload,
              location: { offset: 127, bytes: 4 },
            },
          },
        ],
      }).success,
    ).toBe(false);
  });
});
