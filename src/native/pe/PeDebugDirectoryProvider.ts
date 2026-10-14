import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import type { PeDebugDirectoryPort } from "../../application/binaryDiagnostics/PeDebugDirectoryPort.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import type { InspectPeDebugDirectoryInput } from "../../domain/native/peDebugDirectory.js";
import { err, ok } from "../../domain/result.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { PE_DEBUG_DIRECTORY_PROVIDER } from "../../application/InvestigationProviders.js";
import { parsePeDebugDirectory } from "./PeDebugDirectoryParser.js";

const OPERATION = "inspect_pe_debug_directory";

/** Portable parser over one bounded, identity-checked regular file. */
export class PeDebugDirectoryProvider implements PeDebugDirectoryPort {
  readonly identity = PE_DEBUG_DIRECTORY_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  close(): Promise<void> {
    return this.#resources.close();
  }

  async inspect(
    input: InspectPeDebugDirectoryInput,
    options?: ExecutionOptions,
  ) {
    try {
      const snapshot = await this.#resources.run(() =>
        readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        ),
      );
      return ok(
        parsePeDebugDirectory(
          snapshot.bytes,
          {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          input,
        ),
      );
    } catch (cause) {
      return err(peDebugFailure(cause, input, options?.signal));
    }
  }
}

const peDebugFailurePrimary = (
  cause: unknown,
  input: InspectPeDebugDirectoryInput,
  signal: AbortSignal | undefined,
) => {
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(
      OPERATION,
      input.path,
      cause.message,
      { cause },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, { cause });
  if (signal?.aborted) return new AnalysisCancelledError(OPERATION, { cause });

  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        cause.message,
        {
          max_file_bytes: input.max_file_bytes,
          max_entries: input.max_entries,
        },
        { cause },
      );
    if (cause.reason === "path" || cause.reason === "format")
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: cause.message,
        },
      ]);
  }

  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, input.path, cause.code, {
        cause,
      });
    if (cause.code === "ENOENT" || cause.code === "ENOTDIR")
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected PE image could not be read (${cause.code}): ${input.path}.`,
        },
      ]);
  }

  return new ProviderAdapterError(PE_DEBUG_DIRECTORY_PROVIDER.id, OPERATION, {
    cause,
    diagnostics: {
      path: input.path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};

const peDebugFailure = (
  cause: unknown,
  input: InspectPeDebugDirectoryInput,
  signal: AbortSignal | undefined,
) => {
  const primary = peDebugFailurePrimary(cause, input, signal);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    PE_DEBUG_DIRECTORY_PROVIDER.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation: OPERATION, cause },
  );
  return analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
};
