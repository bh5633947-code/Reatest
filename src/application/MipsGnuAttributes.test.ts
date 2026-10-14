import { describe, expect, it } from "vitest";
import { parseMipsGnuAttributes } from "./MipsGnuAttributes.js";

const u32 = (value: number, little: boolean): number[] => {
  const bytes = Buffer.alloc(4);
  if (little) bytes.writeUInt32LE(value);
  else bytes.writeUInt32BE(value);
  return [...bytes];
};

/** Build `A`, one vendor subsection and one scope, as GNU as and ld lay them out. */
const section = (
  attributes: readonly number[],
  {
    little = true,
    vendor = "gnu",
    scope = 1,
  }: { little?: boolean; vendor?: string; scope?: number } = {},
): Buffer => {
  const scoped = [
    scope,
    ...u32(1 + 4 + attributes.length, little),
    ...attributes,
  ];
  const name = [...Buffer.from(vendor, "latin1"), 0];
  return Buffer.from([
    0x41,
    ...u32(4 + name.length + scoped.length, little),
    ...name,
    ...scoped,
  ]);
};

describe("MIPS GNU attribute parsing", () => {
  it.each([true, false])(
    "reads the FP and MSA ABI tags GCC emits (little=%s)",
    (little) => {
      expect(
        parseMipsGnuAttributes(section([4, 1], { little }), little),
      ).toEqual({ ok: true, value: { fpAbi: 1, msa: null } });
      expect(
        parseMipsGnuAttributes(section([4, 3, 8, 0], { little }), little),
      ).toEqual({ ok: true, value: { fpAbi: 3, msa: 0 } });
    },
  );

  it("decodes multi-byte ULEB128 values and accepts an empty attribute section", () => {
    expect(parseMipsGnuAttributes(section([4, 0x85, 0x01]), true)).toEqual({
      ok: true,
      value: { fpAbi: 133, msa: null },
    });
    expect(parseMipsGnuAttributes(Buffer.from([0x41]), true)).toEqual({
      ok: true,
      value: { fpAbi: null, msa: null },
    });
  });

  it("requires lengths in the ELF byte order", () => {
    expect(
      parseMipsGnuAttributes(section([4, 1], { little: true }), false).ok,
    ).toBe(false);
  });

  it.each([
    ["an unsupported format version", Buffer.from([0x42]), /format version/u],
    ["a truncated subsection length", Buffer.from([0x41, 1, 0]), /truncated/u],
    [
      "a subsection longer than the section",
      Buffer.from([0x41, ...u32(64, true), 0x67, 0x6e, 0x75, 0]),
      /does not fit the section/u,
    ],
    [
      "an unterminated vendor name",
      Buffer.from([0x41, ...u32(7, true), 0x67, 0x6e, 0x75]),
      /unterminated/u,
    ],
    ["another vendor", section([4, 1], { vendor: "arm" }), /non-GNU vendor/u],
    ["section scope", section([4, 1], { scope: 2 }), /sections or symbols/u],
    ["symbol scope", section([4, 1], { scope: 3 }), /sections or symbols/u],
    ["an unknown tag", section([6, 1]), /tag 6/u],
    ["Tag_compatibility", section([32, 0, 0]), /tag 32/u],
    [
      "a repeated FP tag",
      section([4, 1, 4, 1]),
      /duplicate MIPS GNU floating-point/u,
    ],
    ["a repeated MSA tag", section([8, 0, 8, 0]), /duplicate MIPS GNU MSA/u],
    [
      "an unterminated value",
      section([4, 0x81]),
      /malformed MIPS GNU attribute value/u,
    ],
    [
      "a value wider than 32 bits",
      section([4, 0xff, 0xff, 0xff, 0xff, 0x1f]),
      /malformed MIPS GNU attribute value/u,
    ],
  ] as const)("refuses %s", (_label, bytes, reason) => {
    const result = parseMipsGnuAttributes(bytes, true);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(reason);
  });

  it("refuses a scope whose length overruns its subsection", () => {
    const bytes = section([4, 1]);
    // Scope length sits after "A", the subsection length and "gnu\0".
    bytes.writeUInt32LE(64, 1 + 4 + 4 + 1);
    const result = parseMipsGnuAttributes(bytes, true);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/scope length/u);
  });

  it("refuses a second gnu vendor subsection", () => {
    const one = section([4, 1]);
    const result = parseMipsGnuAttributes(
      Buffer.concat([one, one.subarray(1)]),
      true,
    );
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error).toMatch(/duplicate MIPS GNU attribute vendor/u);
  });
});
