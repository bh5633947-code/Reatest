import { truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { ArtifactResourceScope } from "../../../../src/artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../../../src/filesystem/OwnedFileHandle.js";

import {
  compareManagedMembersEvidenceValidated,
  compareManagedMemberPaths,
} from "../../../../src/application/managed/ManagedMemberComparisonService.js";
import { parseBinaryTarget } from "../../../../src/application/BinaryTargetResolver.js";
import { managedMemberComparisonResultSchema } from "../../../../src/domain/managed/managedMemberComparison.js";
import {
  enclosingTypeNames,
  identityOf,
  parseManagedMemberEvidence,
} from "../../../../src/domain/managed/managedMemberComparisonMatch.js";
import { createEvidence } from "../../../../src/domain/evidence.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { jsonValueSchema } from "../../../../src/domain/jsonValue.js";
import { compareManagedMembersInputSchema } from "../../../../src/domain/managed/managedMemberComparison.js";
import { inspectManagedMembersBytes } from "../../../../src/dotnet/ManagedMemberInspector.js";
import { managedPeFixtureTarget } from "../../../../src/dotnet/ManagedPe.fixture.js";
import {
  buildManagedNestedTypeFixture,
  buildManagedPeFixture,
} from "../../../../src/dotnet/ManagedPe.fixture.js";
import {
  MAX_MANAGED_SNAPSHOT_BYTES,
  readManagedSnapshot,
} from "../../../../src/dotnet/ManagedSnapshot.js";
import * as boundedFileBytes from "../../../../src/process/BoundedFileBytes.js";

it.each([
  ["accessibility", 6, 0x0011],
  ["synchronized implementation", 4, 0x0020],
])(
  "reports changed observed method %s despite identical CIL",
  async (_name, flagOffset, flags) => {
    const directory = await createTestTempDirectory("rea-managed-flags-");
    const leftPath = join(directory, "left.dll");
    const rightPath = join(directory, "right.dll");
    const left = buildManagedPeFixture();
    const inspection = inspectManagedMembersBytes(
      left,
      managedPeFixtureTarget(left, leftPath),
    );
    const method = inspection.methods[0];
    if (method === undefined) throw new Error("missing method fixture");
    const right = Buffer.from(left);
    right.writeUInt16LE(flags, method.row_offset + flagOffset);
    await writeFile(leftPath, left);
    await writeFile(rightPath, right);
    const result = await compareManagedMemberPaths({ leftPath, rightPath });
    if (!result.ok) throw result.error;
    const comparison = managedMemberComparisonResultSchema.parse(
      result.value.normalized_result,
    );
    expect(comparison.methods[0]).toMatchObject({
      status: "changed",
      dimensions: ["metadata"],
    });
    expect(comparison.methods[0]?.left?.normalized_il_sha256).toBe(
      comparison.methods[0]?.right?.normalized_il_sha256,
    );
  },
);

type Inspection = ReturnType<typeof inspectManagedMembersBytes>;
const nestedInspection = (
  options: Parameters<typeof buildManagedNestedTypeFixture>[0] = {},
  typeNames?: readonly string[],
) => {
  const bytes = buildManagedNestedTypeFixture(options);
  const target = managedPeFixtureTarget(
    bytes,
    `/fixture/nested-${JSON.stringify(options)}.dll`,
  );
  return {
    target,
    inspection: inspectManagedMembersBytes(
      bytes,
      target,
      typeNames === undefined ? {} : { typeNames },
    ),
  };
};
// Evidence recorded before nesting was read has neither field.
const recordedBefore = ({ nesting_read, types, ...rest }: Inspection) => ({
  ...rest,
  types: types.map(({ enclosing_type_token, ...type }) => type),
});
const compare = (
  left: ReturnType<typeof nestedInspection>,
  right: ReturnType<typeof nestedInspection>,
  edit: {
    readonly left?: (inspection: Inspection) => unknown;
    readonly right?: (inspection: Inspection) => unknown;
  } = {},
) => {
  const observe = (
    { target, inspection }: ReturnType<typeof nestedInspection>,
    change: ((inspection: Inspection) => unknown) | undefined,
  ) =>
    createEvidence(
      target,
      { id: "nested-fixture", name: "Nested fixture", version: "1" },
      {
        operation: "inspect_managed_members",
        parameters: {},
        result: jsonValueSchema.parse(change?.(inspection) ?? inspection),
        confidence: "observed",
        authority: "shipped-artifact",
      },
    );
  const result = compareManagedMembersEvidenceValidated(
    compareManagedMembersInputSchema.parse({
      left: observe(left, edit.left),
      right: observe(right, edit.right),
    }),
  );
  if (!result.ok) throw result.error;
  return managedMemberComparisonResultSchema.parse(
    result.value.normalized_result,
  );
};
const pairs = (comparison: ReturnType<typeof compare>) => {
  const of = (
    items: readonly {
      readonly left: { readonly token: string } | null;
      readonly right: { readonly token: string } | null;
      readonly status: string;
      readonly match: { readonly basis: string; readonly confidence: string };
    }[],
  ) =>
    items.map(({ left, right, status, match }) => [
      left?.token ?? null,
      right?.token ?? null,
      status,
      match.basis,
      match.confidence,
    ]);
  return { methods: of(comparison.methods), fields: of(comparison.fields) };
};
const original = nestedInspection();
const swapped = nestedInspection({ swapEnclosing: true });

describe("managed member comparison of nested types", () => {
  it("pairs members of same-named nested types by their enclosing types", () => {
    // Moving each Inner under the other top-level type turns Fixture.A+Inner
    // from TypeDef 4 on the left into TypeDef 5 on the right.
    expect(pairs(compare(original, swapped))).toEqual({
      methods: [
        [
          "0x06000001",
          "0x06000002",
          "unchanged",
          "exact-il-signature",
          "exact",
        ],
        [
          "0x06000002",
          "0x06000001",
          "unchanged",
          "exact-il-signature",
          "exact",
        ],
        [
          "0x06000003",
          "0x06000003",
          "unchanged",
          "exact-il-signature",
          "exact",
        ],
      ],
      fields: [
        ["0x04000001", "0x04000002", "unchanged", "field-signature", "exact"],
        ["0x04000002", "0x04000001", "unchanged", "field-signature", "exact"],
      ],
    });
  });

  it("reports bodies swapped between same-named nested types as changed", () => {
    // Give each Inner.M its own CIL, then swap the bodies between A and B.
    const bodies =
      (byToken: Readonly<Record<string, string>>) =>
      (inspection: Inspection) => ({
        ...inspection,
        methods: inspection.methods.map((method) => {
          const digest = byToken[method.token];
          return digest === undefined || method.body.status !== "present"
            ? method
            : {
                ...method,
                body: {
                  ...method.body,
                  il_sha256: digest,
                  normalized_il_sha256: digest,
                },
              };
        }),
      });
    // Fixture.A+Inner.M is MethodDef 1 on the left and MethodDef 2 on the right.
    const comparison = compare(original, swapped, {
      left: bodies({
        "0x06000001": "a".repeat(64),
        "0x06000002": "b".repeat(64),
      }),
      right: bodies({
        "0x06000002": "b".repeat(64),
        "0x06000001": "a".repeat(64),
      }),
    });

    expect(pairs(comparison).methods.slice(0, 2)).toEqual([
      ["0x06000001", "0x06000002", "changed", "exact-signature", "exact"],
      ["0x06000002", "0x06000001", "changed", "exact-signature", "exact"],
    ]);
    expect(
      comparison.methods.slice(0, 2).map(({ dimensions }) => dimensions),
    ).toEqual([["cil"], ["cil"]]);
    expect(comparison.summary).toMatchObject({ changed: 2 });
  });

  it("keeps bare nested names when either side cannot name its enclosing types", () => {
    const bare = pairs(
      compare(original, swapped, {
        left: recordedBefore,
        right: recordedBefore,
      }),
    );

    expect(bare).not.toEqual(pairs(compare(original, swapped)));
    expect(pairs(compare(original, swapped, { left: recordedBefore }))).toEqual(
      bare,
    );
    expect(
      pairs(compare(original, swapped, { right: recordedBefore })),
    ).toEqual(bare);
    // Selecting Inner leaves its enclosing types out of the left Evidence.
    const selected = nestedInspection({}, ["Inner"]);
    expect(enclosingTypeNames(selected.inspection)).toBe(null);
    // A malformed NestedClass row leaves nesting unread on the right.
    const malformed = nestedInspection({
      swapEnclosing: true,
      nestedClassRows: [
        [4, 3],
        [5, 2],
        [6, 4],
        [6, 5],
      ],
    });
    expect(malformed.inspection.nesting_read).toBe(false);
    expect(pairs(compare(original, malformed))).toEqual(bare);
  });

  it("does not pair a nested type with a top-level type of the same name", () => {
    const topLevel = nestedInspection({ nestedClassRows: [] });

    // Evidence of an assembly without nested types still names its types.
    expect(enclosingTypeNames(topLevel.inspection)?.get("0x02000004")).toEqual([
      "Inner",
    ]);
    expect(
      pairs(compare(original, topLevel)).methods.filter(
        ([left, right]) => left !== null && right !== null,
      ),
    ).toEqual([]);
  });
});

describe("managed nested type names", () => {
  it("keeps a top-level name containing the separator apart from nesting", () => {
    // Rename the right Fixture.B to a top-level type spelled like A's nesting.
    const spelled = compare(original, original, {
      right: (inspection) => ({
        ...inspection,
        types: inspection.types.map((type) =>
          type.token === "0x02000005"
            ? {
                ...type,
                full_name: "Fixture.A+Inner",
                enclosing_type_token: null,
              }
            : type,
        ),
        methods: inspection.methods.map((method) =>
          method.declaring_type_token === "0x02000005"
            ? { ...method, declaring_type: "Fixture.A+Inner" }
            : method,
        ),
      }),
    });

    // Joined names would make both sides' Fixture.A+Inner one ambiguous group.
    expect(pairs(spelled).methods).toEqual([
      ["0x06000001", "0x06000001", "unchanged", "exact-il-signature", "exact"],
      ["0x06000003", "0x06000003", "unchanged", "exact-il-signature", "exact"],
      ["0x06000002", "0x06000002", "unchanged", "exact-il-signature", "exact"],
    ]);
  });

  it("warns of an undecoded counterpart only for the same enclosing type", () => {
    // Keep only Fixture.B+Inner.M on the right, with an undecoded signature.
    const comparison = compare(original, original, {
      right: (inspection) => ({
        ...inspection,
        methods: inspection.methods
          .filter(({ token }) => token === "0x06000002")
          .map((method) => ({
            ...method,
            signature: {
              ...method.signature,
              raw_sha256: "c".repeat(64),
              parse_status: "malformed",
            },
          })),
      }),
    });
    const warned = comparison.methods.map(({ left, right, limitations }) => [
      left?.token ?? null,
      right?.token ?? null,
      limitations.some((limitation) =>
        limitation.startsWith("counterpart-signature-not-decoded"),
      ),
    ]);

    expect(warned).toContainEqual(["0x06000001", null, false]);
    expect(warned).toContainEqual(["0x06000002", null, true]);
  });

  it("names a type by its enclosing types, outermost first, within bounds", () => {
    const { inspection } = original;
    const names = enclosingTypeNames(inspection);

    expect(inspection.types.map(({ token }) => names?.get(token))).toEqual([
      ["<Module>"],
      ["Fixture.A"],
      ["Fixture.B"],
      ["Fixture.A", "Inner"],
      ["Fixture.B", "Inner"],
      ["Fixture.A", "Inner", "Leaf"],
    ]);
    // A list keeps a name that contains the separator apart from nesting.
    expect(
      identityOf({ declaring_type: ["Fixture.A", "Inner"], name: "M" }),
    ).not.toBe(identityOf({ declaring_type: "Fixture.A+Inner", name: "M" }));
    // Names do not depend on whether a nested type precedes its enclosing type.
    expect(
      enclosingTypeNames({
        ...inspection,
        types: [...inspection.types].reverse(),
      }),
    ).toEqual(names);
    expect(enclosingTypeNames({ ...inspection, nesting_read: false })).toBe(
      null,
    );
    // A cycle through Leaf cannot be named.
    expect(
      enclosingTypeNames({
        ...inspection,
        types: inspection.types.map((type) =>
          type.token === "0x02000002"
            ? { ...type, enclosing_type_token: "0x02000006" }
            : type,
        ),
      }),
    ).toBe(null);
    const chain = (depth: number) =>
      enclosingTypeNames({
        nesting_read: true,
        types: Array.from({ length: depth }, (_, index) => ({
          ...inspection.types[1]!,
          token: `0x02${String(index + 1).padStart(6, "0")}`,
          enclosing_type_token:
            index === 0 ? null : `0x02${String(index).padStart(6, "0")}`,
        })),
      });
    expect(chain(64)?.size).toBe(64);
    expect(chain(65)).toBe(null);
  });
});

describe("managed member comparison subject identity", () => {
  it("rejects authenticated member Evidence whose subject digest differs from its artifact", () => {
    const bytes = buildManagedPeFixture();
    const target = managedPeFixtureTarget(bytes, "/fixture/mismatch.dll");
    const inspection = inspectManagedMembersBytes(bytes, target);
    const otherDigest = "b".repeat(64);
    const mismatched = createEvidence(
      target,
      {
        id: "partial-fixture",
        name: "Partial fixture",
        version: "1",
      },
      {
        operation: "inspect_managed_members",
        parameters: {},
        result: jsonValueSchema.parse({
          ...inspection,
          artifact: { ...inspection.artifact, sha256: otherDigest },
          identity_scope: {
            ...inspection.identity_scope,
            requires_artifact_sha256: otherDigest,
          },
        }),
      },
    );
    const aligned = createEvidence(
      target,
      {
        id: "partial-fixture",
        name: "Partial fixture",
        version: "1",
      },
      {
        operation: "inspect_managed_members",
        parameters: {},
        result: inspection,
      },
    );
    const unavailableSubject = createEvidence(
      undefined,
      {
        id: "partial-fixture",
        name: "Partial fixture",
        version: "1",
      },
      {
        operation: "inspect_managed_members",
        parameters: {},
        result: inspection,
      },
    );

    expect(() => parseManagedMemberEvidence(mismatched)).toThrow(
      `Managed Evidence inspect_managed_members (${mismatched.evidence_id}) subject SHA-256 ${target.sha256} does not match normalized artifact SHA-256 ${otherDigest}`,
    );
    expect(parseManagedMemberEvidence(aligned).result.artifact.sha256).toBe(
      target.sha256,
    );
    expect(
      parseManagedMemberEvidence(unavailableSubject).result.artifact.sha256,
    ).toBe(target.sha256);
  });
});

describe("managed member comparison path workflow", () => {
  it("preserves undecoded signatures as unknown through content-addressed partial Evidence", () => {
    const observe = (signature: number, path: string) => {
      const bytes = buildManagedPeFixture({
        methodSignature: Buffer.from([signature]),
      });
      const target = managedPeFixtureTarget(bytes, path);
      const inspection = inspectManagedMembersBytes(bytes, target);
      return createEvidence(
        target,
        { id: "partial-fixture", name: "Partial fixture", version: "1" },
        {
          operation: "inspect_managed_members",
          parameters: {},
          result: jsonValueSchema.parse({
            ...inspection,
            coverage: { ...inspection.coverage, state: "partial" },
          }),
          confidence: "observed",
          authority: "shipped-artifact",
        },
      );
    };
    const input = compareManagedMembersInputSchema.parse({
      left: observe(0xff, "/tmp/partial-left.dll"),
      right: observe(0xfe, "/tmp/partial-right.dll"),
    });
    const result = compareManagedMembersEvidenceValidated(input);
    if (!result.ok) throw result.error;
    const comparison = managedMemberComparisonResultSchema.parse(
      result.value.normalized_result,
    );
    expect(comparison.coverage.status).toBe("partial");
    expect(comparison.matching.structural_method_shape).toBe(0);
    expect(comparison.methods).toHaveLength(2);
    expect(
      comparison.methods.every(
        ({ status, match }) =>
          status === "unknown" && match.status === "unmatched",
      ),
    ).toBe(true);
  });

  it("compares two local paths and returns derived Evidence", async () => {
    const directory = await createTestTempDirectory("rea-managed-compare-");
    const leftPath = join(directory, "left.dll");
    const rightPath = join(directory, "right.dll");
    await writeFile(leftPath, buildManagedPeFixture());
    await writeFile(
      rightPath,
      buildManagedPeFixture({ methodName: "Renamed" }),
    );

    const result = await compareManagedMemberPaths({
      leftPath,
      rightPath,
    });

    if (!result.ok) throw result.error;
    expect(result.value).toMatchObject({
      operation: "compare_managed_members",
      confidence: "inferred",
      authority: "analyst-inference",
    });
    expect(result.value.parameters).toMatchObject({
      left_path: leftPath,
      right_path: rightPath,
    });
    expect(result.value.locations).toEqual([
      { kind: "artifact-path", path: leftPath },
      { kind: "artifact-path", path: rightPath },
    ]);
    expect(
      managedMemberComparisonResultSchema.parse(result.value.normalized_result)
        .matching.exact_il_signature,
    ).toBe(1);
  });

  it("reports an unopenable path with the path that failed", async () => {
    const directory = await createTestTempDirectory("rea-managed-missing-");
    const leftPath = join(directory, "missing.dll");
    const rightPath = join(directory, "right.dll");
    await writeFile(rightPath, buildManagedPeFixture());

    const result = await compareManagedMemberPaths({ leftPath, rightPath });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("BinaryTargetError");
    expect(projectAnalysisError(result.error)).toMatchObject({
      details: { path: expect.stringContaining("missing.dll") },
    });
  });
});

describe("managed comparison post-admission read failures", () => {
  it.each([
    ["left", "disappearance", "ENOENT"],
    ["left", "permission denial", "EACCES"],
    ["right", "disappearance", "ENOENT"],
    ["right", "permission denial", "EACCES"],
  ])(
    "classifies a %s-side %s during the post-resolution read",
    async (side, _name, code) => {
      const directory = await createTestTempDirectory(
        "rea-managed-read-failure-",
      );
      const leftPath = join(directory, "left.dll");
      const rightPath = join(directory, "right.dll");
      await writeFile(leftPath, buildManagedPeFixture());
      await writeFile(rightPath, buildManagedPeFixture());

      const result = await compareManagedMemberPaths(
        { leftPath, rightPath },
        {
          resolveTarget: parseBinaryTarget,
          readSnapshot: async (path, operation, options) => {
            if (path === (side === "left" ? leftPath : rightPath)) {
              const failure = Object.assign(new Error(`read failed: ${code}`), {
                code,
              });
              throw failure;
            }
            return readManagedSnapshot(path, operation, options);
          },
        },
      );

      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error._tag).toBe("BinaryTargetError");
      expect(projectAnalysisError(result.error)).toMatchObject({
        details: { path: side === "left" ? leftPath : rightPath },
      });
      if (side === "right")
        expect(result.error.partialObservation).toMatchObject({
          operation: "inspect_managed_members",
          subject: {
            local_path: leftPath,
            digest: { sha256: expect.stringMatching(/^[0-9a-f]{64}$/u) },
          },
        });
      else expect(result.error.partialObservation).toBeUndefined();
      if (code === "EACCES")
        expect(projectAnalysisError(result.error)).toMatchObject({
          code: "access_denied",
        });
    },
  );
});

describe("managed comparison snapshot admission and cleanup", () => {
  it("rejects a sparse oversized snapshot through the default reader before reading it", async () => {
    const directory = await createTestTempDirectory(
      "rea-managed-oversized-snapshot-",
    );
    const leftPath = join(directory, "oversized.dll");
    const rightPath = join(directory, "right.dll");
    const fixture = buildManagedPeFixture();
    await writeFile(leftPath, Buffer.alloc(0));
    await truncate(leftPath, MAX_MANAGED_SNAPSHOT_BYTES + 1);
    await writeFile(rightPath, fixture);
    const template = managedPeFixtureTarget(fixture);
    const read = vi.spyOn(boundedFileBytes, "readBoundedFileBytes");
    try {
      const result = await compareManagedMemberPaths(
        { leftPath, rightPath },
        {
          resolveTarget: async (path) => ({
            ok: true,
            value: { ...template, path },
          }),
        },
      );

      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error).toMatchObject({
        _tag: "AnalysisResourceConstraintError",
        operation: "compare_managed_members",
        reportedLimits: {
          max_snapshot_bytes: MAX_MANAGED_SNAPSHOT_BYTES,
        },
      });
      expect(read).not.toHaveBeenCalled();
    } finally {
      read.mockRestore();
    }
  });

  it("retries a transient snapshot close failure through the same resource owner", async () => {
    const directory = await createTestTempDirectory(
      "rea-managed-compare-close-",
    );
    const leftPath = join(directory, "left.dll");
    const rightPath = join(directory, "right.dll");
    await writeFile(leftPath, buildManagedPeFixture());
    await writeFile(rightPath, buildManagedPeFixture());
    const resources = new ArtifactResourceScope();
    const originalClose = OwnedFileHandle.prototype.close;
    const owners: OwnedFileHandle[] = [];
    let attempts = 0;
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (this: OwnedFileHandle) {
        owners.push(this);
        attempts += 1;
        if (attempts === 1) throw new Error("injected transient close failure");
        await originalClose.call(this);
      });
    try {
      const result = await compareManagedMemberPaths(
        { leftPath, rightPath },
        {},
        resources,
      );

      expect(result.ok).toBe(true);
      expect(owners[0]).toBe(owners[1]);
      expect(attempts).toBe(3);
    } finally {
      close.mockRestore();
      await resources.close();
    }
  });

  it("projects persistent snapshot cleanup failure and retains its exact owner", async () => {
    const directory = await createTestTempDirectory(
      "rea-managed-compare-cleanup-",
    );
    const leftPath = join(directory, "left.dll");
    const rightPath = join(directory, "right.dll");
    await writeFile(leftPath, buildManagedPeFixture());
    await writeFile(rightPath, buildManagedPeFixture());
    const resources = new ArtifactResourceScope();
    const cleanupCause = new Error("injected persistent close failure");
    const owners: OwnedFileHandle[] = [];
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (this: OwnedFileHandle) {
        owners.push(this);
        throw cleanupCause;
      });
    let result: Awaited<ReturnType<typeof compareManagedMemberPaths>>;
    try {
      result = await compareManagedMemberPaths(
        { leftPath, rightPath },
        {},
        resources,
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(projectAnalysisError(result.error)).toMatchObject({
        code: "cleanup_incomplete",
        details: { cleanup: "incomplete", resources: [leftPath] },
      });
      expect(owners[0]).toBe(owners[1]);
      expect(owners[0]?.handle.fd).toBeGreaterThanOrEqual(0);
    } finally {
      close.mockRestore();
      await resources.close();
    }
  });
});

describe("managed comparison target identity", () => {
  it("rejects a file that changes after target identity is resolved", async () => {
    const directory = await createTestTempDirectory(
      "rea-managed-compare-race-",
    );
    const leftPath = join(directory, "left.dll");
    const rightPath = join(directory, "right.dll");
    await writeFile(leftPath, buildManagedPeFixture());
    await writeFile(rightPath, buildManagedPeFixture());
    const replacement = buildManagedPeFixture({
      methodName: "ChangedAfterOpen",
    });

    const result = await compareManagedMemberPaths(
      { leftPath, rightPath },
      {
        resolveTarget: async (path) => {
          const target = await parseBinaryTarget(path);
          if (target.ok && path === leftPath)
            await writeFile(path, replacement);
          return target;
        },
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("EvidenceIntegrityError");
    expect(result.error.message).toContain(leftPath);
  });
});
