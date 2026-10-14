import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { peDebugDirectoryFixture } from "../../../src/native/pe/PeDebugDirectory.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { mcpTest, type TestMcp } from "../../support/mcp/mcpFixture.js";

const connect = async (mcp: TestMcp) => {
  const session = createTestBinarySession(() => {
    throw new Error(
      "PE debug-directory inspection must not start a deep provider",
    );
  });
  const client = await mcp.connect(createServer({ kind: "session", session }));
  return { client, session };
};

mcpTest(
  "advertises inspect_pe_debug_directory and reads a CodeView RSDS record",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const advertised = (await client.listTools()).tools.find(
        (tool) => tool.name === "inspect_pe_debug_directory",
      );
      expect(advertised?.annotations).toMatchObject({
        readOnlyHint: false,
        idempotentHint: true,
      });
      const root = await createTestTempDirectory("rea-pe-debug-mcp-");
      const path = join(root, "sample.exe");
      await writeFile(path, peDebugDirectoryFixture().bytes);
      const response = await client.callTool({
        name: "inspect_pe_debug_directory",
        arguments: { path },
      });
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      const evidence = toolContract(
        "inspect_pe_debug_directory",
      ).outputSchema.parse(response.structuredContent);
      expect(
        evidence.normalized_result.entries[0]?.payload.decoded,
      ).toMatchObject({
        kind: "codeview_rsds",
        pdb_file_name: "sample.pdb",
        age: 7,
      });
      const missing = join(root, "plain.exe");
      await writeFile(missing, peDebugDirectoryFixture(false, []).bytes);
      const absent = await client.callTool({
        name: "inspect_pe_debug_directory",
        arguments: { path: missing },
      });
      expect(absent.isError).not.toBe(true);
      const absentEvidence = toolContract(
        "inspect_pe_debug_directory",
      ).outputSchema.parse(absent.structuredContent);
      expect(absentEvidence.normalized_result.entries).toEqual([]);
      expect(absentEvidence.normalized_result.directory).toBeNull();
    } finally {
      await session.close();
    }
  },
);

mcpTest(
  "requires an absolute path for inspect_pe_debug_directory",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const response = await client.callTool({
        name: "inspect_pe_debug_directory",
        arguments: { path: "sample.exe" },
      });
      expect(response.isError).toBe(true);
      expect(parseMcpToolError(response).error).toMatchObject({
        code: "invalid_request",
        details: { operation: "inspect_pe_debug_directory" },
      });
    } finally {
      await session.close();
    }
  },
);
