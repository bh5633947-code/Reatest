import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { PeDebugDirectoryService } from "./PeDebugDirectoryService.js";
import { PE_DEBUG_DIRECTORY_PROVIDER } from "../InvestigationProviders.js";
import { inspectPeDebugDirectoryInputSchema } from "../../domain/native/peDebugDirectory.js";
import { parsePeDebugDirectory } from "../../native/pe/PeDebugDirectoryParser.js";
import { peDebugDirectoryFixture } from "../../native/pe/PeDebugDirectory.fixture.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { ok } from "../../domain/result.js";

const observedReport = () => {
  const { bytes } = peDebugDirectoryFixture();
  return parsePeDebugDirectory(
    bytes,
    {
      path: "/fixtures/sample.exe",
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    },
    inspectPeDebugDirectoryInputSchema.parse({ path: "/fixtures/sample.exe" }),
  );
};

it("rejects a relative path before reading", async () => {
  let calls = 0;
  const service = new PeDebugDirectoryService({
    identity: PE_DEBUG_DIRECTORY_PROVIDER,
    inspect: () => {
      calls += 1;
      return Promise.resolve(ok(observedReport()));
    },
  });
  const result = await service.inspect({ path: "sample.exe" });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisInputError);
  expect(calls).toBe(0);
});

it("records the selected artifact and the debug-directory file range", async () => {
  const report = observedReport();
  const result = await new PeDebugDirectoryService({
    identity: PE_DEBUG_DIRECTORY_PROVIDER,
    inspect: () => Promise.resolve(ok(report)),
  }).inspect({ path: report.artifact.path });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "observed",
    subject: { format: "pe" },
    normalized_result: report,
  });
  expect(result.value.locations).toEqual(
    expect.arrayContaining([
      { kind: "artifact-path", path: report.artifact.path },
      {
        kind: "file-offset-range",
        start: report.directory?.location.offset,
        end:
          (report.directory?.location.offset ?? 0) +
          (report.directory?.location.bytes ?? 0),
      },
    ]),
  );
});

it("discards an observation if the caller cancels while the provider completes", async () => {
  const report = observedReport();
  const controller = new AbortController();
  const service = new PeDebugDirectoryService({
    identity: PE_DEBUG_DIRECTORY_PROVIDER,
    inspect: () => {
      controller.abort();
      return Promise.resolve(ok(report));
    },
  });
  expect(
    await service.inspect(
      { path: report.artifact.path },
      { signal: controller.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
});
