import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  InspectPeDebugDirectoryInput,
  PeDebugDirectory,
} from "../../domain/native/peDebugDirectory.js";
import type { Result } from "../../domain/result.js";

/** Stable read and PE debug-directory decoding, independent of a disassembler session. */
export interface PeDebugDirectoryPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectPeDebugDirectoryInput,
    options?: ExecutionOptions,
  ): Promise<Result<PeDebugDirectory, AnalysisError>>;
}
