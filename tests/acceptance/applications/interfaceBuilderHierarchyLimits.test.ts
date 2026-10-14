import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { build } from "plist";
import { expect } from "vitest";
import { z } from "zod";

import { toolContract } from "../../../src/contracts/toolContracts.js";
import { interfaceBuilderSummarySchema } from "../../../src/domain/analysisView/interfaceBuilderView.js";
import { interfaceBuilderAnalysisSchema } from "../../../src/domain/apple/interfaceBuilderGraph.js";
import { thinMach } from "../../../src/domain/binaryTarget.fixture.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const archive = (objects: readonly string[], hierarchy: readonly string[]) =>
  build({
    "com.apple.ibtool.document.objects": Object.fromEntries(
      objects.map((id) => [id, { class: "UIView" }]),
    ),
    "com.apple.ibtool.document.hierarchy": hierarchy.map((objectID) => ({
      objectID,
    })),
  });

cliTest.for([
  {
    name: "a later document's root is omitted",
    archives: [
      ["First.nib", archive(["first"], ["first"])],
      ["Second.nib", archive(["second"], ["second"])],
    ] as const,
    expectedComplete: [true, false],
    incompleteDocument: "Second.nib",
    omittedEdges: 1,
    unresolvedEdge: false,
  },
  {
    name: "a retained hierarchy edge's endpoint is omitted",
    archives: [
      ["Single.nib", archive(["kept", "omitted"], ["omitted"])],
    ] as const,
    expectedComplete: [false],
    incompleteDocument: "Single.nib",
    omittedEdges: 0,
    unresolvedEdge: true,
  },
])(
  "reports partial hierarchy through CLI and stdio MCP when $name",
  async (
    {
      archives,
      expectedComplete,
      incompleteDocument,
      omittedEdges,
      unresolvedEdge,
    },
    { cli },
  ) => {
    const root = await createTestTempDirectory("rea-ib-hierarchy-limits-");
    const app = join(root, "Fixture.app");
    const contents = join(app, "Contents");
    const resources = join(contents, "Resources");
    await mkdir(resources, { recursive: true });
    await mkdir(join(contents, "MacOS"));
    await writeFile(
      join(contents, "MacOS", "Fixture"),
      thinMach(0xfeedfacf, 0x0100000c),
    );
    await writeFile(
      join(contents, "Info.plist"),
      build({ CFBundleExecutable: "Fixture" }),
    );
    for (const [name, text] of archives)
      await writeFile(join(resources, name), text);

    const output = await cli.run({
      arguments: [
        "decode-interface-builder",
        app,
        "--max-objects",
        "2",
        "--json",
      ],
      environment: { REA_LOG_LEVEL: "silent", REA_ANALYSIS_PROVIDER: "auto" },
    });
    expect(output.exitCode, output.stdout + output.stderr).toBe(0);
    const contract = toolContract("decode_interface_builder");
    const evidence = contract.outputSchema.parse(output.json);
    const report = interfaceBuilderAnalysisSchema.parse(
      evidence.normalized_result,
    );

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [resolve("scripts/rea.mjs"), "mcp"],
      env: {
        PATH: process.env.PATH ?? "",
        ...(process.platform === "win32"
          ? {
              SystemRoot: process.env.SystemRoot!,
              TEMP: tmpdir(),
              TMP: tmpdir(),
            }
          : {}),
        REA_LOG_LEVEL: "silent",
        REA_ANALYSIS_PROVIDER: "auto",
      },
      stderr: "pipe",
    });
    transport.stderr?.on("data", () => undefined);
    const client = new Client({
      name: "interface-builder-hierarchy-limits",
      version: "1",
    });
    try {
      await client.connect(transport);
      const opened = await client.callTool({
        name: "open_binary",
        arguments: { path: app },
      });
      expect(opened.isError, JSON.stringify(opened)).not.toBe(true);
      const complete = await client.callTool({
        name: contract.name,
        arguments: { max_objects: 2 },
      });
      expect(complete.isError, JSON.stringify(complete)).not.toBe(true);
      const mcp = contract.outputSchema.parse(complete.structuredContent);
      expect(mcp.normalized_result).toEqual(report);
      const summarized = await client.callTool({
        name: contract.name,
        arguments: { max_objects: 2, detail: "summary" },
      });
      expect(summarized.isError, JSON.stringify(summarized)).not.toBe(true);
      const summary = z
        .object({
          kind: z.literal("summary"),
          parent_evidence_id: z.string(),
          summary: interfaceBuilderSummarySchema,
        })
        .parse(parseEvidence(summarized.structuredContent).normalized_result);
      expect(summary.parent_evidence_id).toBe(mcp.evidence_id);
      expect(summary.summary.documents).toEqual(report.documents);
      expect(summary.summary.truncated).toBe(true);
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }

    expect(
      report.documents.map(({ hierarchy_complete }) => hierarchy_complete),
    ).toEqual(expectedComplete);
    expect(report.graph.coverage).toContainEqual(
      expect.objectContaining({
        facet: `hierarchy:Contents/Resources/${incompleteDocument}`,
        status: "partial",
        reason: "graph_limit_reached",
        examined: 1,
        omitted: omittedEdges,
      }),
    );
    expect(report.graph.truncated).toBe(true);
    expect(report.graph.nodes).toHaveLength(2);
    expect(report.graph.edges).toHaveLength(1);
    if (unresolvedEdge)
      expect(report.graph.edges[0]).toMatchObject({
        relation: "contains",
        resolution: "unresolved",
        to: null,
        reason: "endpoint_omitted_by_object_limit",
      });
    const ids = new Set(report.graph.nodes.map(({ id }) => id));
    expect(
      report.graph.edges.every(
        ({ from, to }) => ids.has(from) && (to === null || ids.has(to)),
      ),
    ).toBe(true);
    for (const [name, text] of archives)
      expect(await readFile(join(resources, name), "utf8")).toBe(text);
  },
);
