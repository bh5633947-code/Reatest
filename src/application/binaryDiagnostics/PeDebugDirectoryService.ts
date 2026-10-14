import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { PeDebugDirectoryPort } from "./PeDebugDirectoryPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectPeDebugDirectoryInputSchema,
  peDebugDirectorySchema,
  type PeDebugDirectory,
} from "../../domain/native/peDebugDirectory.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_pe_debug_directory";

/** Shared caller validation, output parsing and Evidence provenance for CLI and MCP. */
export class PeDebugDirectoryService {
  constructor(readonly provider: PeDebugDirectoryPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectPeDebugDirectoryInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const result = await this.provider.inspect(input.data, options);
    if (!result.ok) return result;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const report = peDebugDirectorySchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      report.data.artifact.bytes > input.data.max_file_bytes ||
      report.data.coverage.entries > input.data.max_entries
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "PE debug-directory provider returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    return ok(
      createEvidence(
        {
          path: value.artifact.path,
          format: "pe",
          sha256: value.artifact.sha256,
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.data,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: locationsFor(value),
        },
      ),
    );
  }
}

const locationsFor = (value: PeDebugDirectory) => [
  { kind: "artifact-path" as const, path: value.artifact.path },
  ...(value.directory === null
    ? []
    : [
        {
          kind: "file-offset-range" as const,
          start: value.directory.location.offset,
          end: value.directory.location.offset + value.directory.location.bytes,
        },
      ]),
];
