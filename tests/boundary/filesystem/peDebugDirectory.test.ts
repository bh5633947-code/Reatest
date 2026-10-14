import { symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createPeDebugDirectoryService } from "../../../src/composition/binaryDiagnostics.js";
import {
  peDebugDirectoryFixture,
  reproPayload,
  rsdsPayload,
} from "../../../src/native/pe/PeDebugDirectory.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

describe("PE debug-directory stable filesystem boundary", () => {
  it("reports non-file and malformed PE selections as caller input errors", async () => {
    const root = await createTestTempDirectory("rea-pe-debug-files-");
    const path = join(root, "image.exe");
    const alias = join(root, "alias.exe");
    const malformed = join(root, "malformed.exe");
    await writeFile(path, peDebugDirectoryFixture().bytes);
    await writeFile(malformed, Buffer.from("not a PE image"));
    await symlink(path, alias);
    const service = createPeDebugDirectoryService();
    for (const [candidate, reason] of [
      [root, "invalid_format"],
      [alias, "invalid_format"],
      [malformed, "invalid_format"],
      [join(root, "missing.exe"), "invalid_value"],
      [join(path, "child.exe"), "invalid_value"],
    ] as const) {
      const result = await service.inspect({ path: candidate });
      if (result.ok) throw new Error("Expected file acquisition failure");
      expect(result.error).toMatchObject({
        _tag: "AnalysisInputError",
        operation: "inspect_pe_debug_directory",
        issues: [
          {
            path: ["path"],
            reason,
            message: expect.any(String),
          },
        ],
      });
    }
  });

  it("returns typed resource and cancellation failures", async () => {
    const root = await createTestTempDirectory("rea-pe-debug-budget-");
    const path = join(root, "image.exe");
    await writeFile(
      path,
      peDebugDirectoryFixture(false, [rsdsPayload(), reproPayload()]).bytes,
    );
    const service = createPeDebugDirectoryService();
    for (const input of [
      { path, max_file_bytes: 64 },
      { path, max_entries: 1 },
    ]) {
      const result = await service.inspect(input);
      if (result.ok) throw new Error("Expected resource budget failure");
      expect(result.error._tag).toBe("AnalysisResourceConstraintError");
    }
    const cancelled = await service.inspect(
      { path },
      { signal: AbortSignal.abort() },
    );
    if (cancelled.ok) throw new Error("Expected cancellation");
    expect(cancelled.error._tag).toBe("AnalysisCancelledError");
  });
});
