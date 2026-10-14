import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import { peDebugDirectoryFixture } from "../../src/native/pe/PeDebugDirectory.fixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "reports CodeView RSDS facts through the public CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-pe-debug-cli-");
    const path = join(root, "sample.exe");
    await writeFile(path, peDebugDirectoryFixture().bytes);
    const result = await cli.run({
      arguments: ["inspect-pe-debug-directory", path, "--json"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract(
      "inspect_pe_debug_directory",
    ).outputSchema.parse(result.json);
    expect(
      evidence.normalized_result.entries[0]?.payload.decoded,
    ).toMatchObject({
      kind: "codeview_rsds",
      pdb_file_name: "sample.pdb",
      age: 7,
    });
  },
);

cliTest(
  "returns an empty inventory when the debug directory is absent",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-pe-debug-cli-missing-");
    const path = join(root, "plain.exe");
    await writeFile(path, peDebugDirectoryFixture(false, []).bytes);
    const result = await cli.run({
      arguments: ["inspect-pe-debug-directory", path, "--json"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract(
      "inspect_pe_debug_directory",
    ).outputSchema.parse(result.json);
    expect(evidence.normalized_result.directory).toBeNull();
    expect(evidence.normalized_result.limitations.join("\n")).toContain(
      "does not prove the image was built without debug information",
    );
  },
);

cliTest("reports a malformed PE as invalid input", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-pe-debug-cli-malformed-");
  const path = join(root, "broken.exe");
  await writeFile(path, Buffer.from("not a PE image"));
  const result = await cli.run({
    arguments: ["inspect-pe-debug-directory", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    details: { operation: "inspect_pe_debug_directory" },
  });
});
