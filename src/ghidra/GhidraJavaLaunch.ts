import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { posix, win32 } from "node:path";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import type { spawnOwnedProviderProcess } from "../process/ProviderProcess.js";

/** Complete release configuration and warnings share this retained byte budget. */
export const GHIDRA_LAUNCH_SUPPORT_OUTPUT_BYTES = 64 * 1024;

/** Keep probe phase and its owned outcome together, including unresolved cleanup. */
export class GhidraLaunchSupportError extends Error {
  constructor(
    readonly phase: "-envvars" | "-vmargs",
    cause: unknown,
  ) {
    super(`Ghidra LaunchSupport ${phase} failed`, { cause });
    this.name = "GhidraLaunchSupportError";
  }

  get ownedFailure(): OwnedCommandFailure | undefined {
    return this.cause instanceof OwnedCommandFailure ? this.cause : undefined;
  }

  get outcome() {
    const failure = this.ownedFailure;
    const snapshot = failure?.snapshot;
    if (snapshot == null) return undefined;
    return {
      stdout: snapshot.stdout.text,
      stderr: snapshot.stderr.text,
      stdoutBytes: snapshot.stdout.observedBytes,
      stderrBytes: snapshot.stderr.observedBytes,
      stdoutTruncated: snapshot.stdout.observedBytes > snapshot.stdout.bytes,
      stderrTruncated: snapshot.stderr.observedBytes > snapshot.stderr.bytes,
      outputTruncated: snapshot.diagnosticTruncated === true,
      // Cancellation alone does not prove that a kill caused the observed exit.
      killed:
        typeof snapshot.signal === "string"
          ? true
          : failure?.reason === "process" && snapshot.exitCode != null
            ? false
            : null,
      exitCode: snapshot.exitCode ?? null,
      signal: snapshot.signal ?? null,
    };
  }
}

/** JVM option environments remove quotes, including quotes inside an option. */
const jvmEnvironmentArguments = (value: string): readonly string[] => {
  const arguments_: string[] = [];
  let argument = "";
  let quote: "'" | '"' | undefined;
  for (const character of value) {
    if (quote !== undefined) {
      if (character === quote) quote = undefined;
      else argument += character;
    } else if (character === "'" || character === '"') quote = character;
    else if (/\s/u.test(character)) {
      if (argument !== "") arguments_.push(argument);
      argument = "";
    } else argument += character;
  }
  if (quote !== undefined)
    throw new Error(
      "Invalid quoted Ghidra LaunchSupport JVM environment option",
    );
  if (argument !== "") arguments_.push(argument);
  return arguments_;
};

const rejectJvmPlatformOverrides = (arguments_: readonly string[]): void => {
  if (
    arguments_.some((argument) => /^-Dos\.(?:arch|name)(?:=|$)/u.test(argument))
  )
    throw new Error(
      "Ghidra LaunchSupport may not override os.arch or os.name; the native decompiler was validated for the inspected JVM platform.",
    );
};

/** Launch coordinates obtained from Ghidra's own release configuration helper. */
export const ghidraJavaLaunch = async (options: {
  readonly platform: NodeJS.Platform;
  readonly analyzeHeadlessPath: string;
  readonly javaHome: string;
  readonly javaVmName?: string;
  readonly homeRoot: string;
  readonly configRoot: string;
  readonly cacheRoot: string;
  readonly tempRoot: string;
  readonly arguments: readonly string[];
  readonly environment: NodeJS.ProcessEnv;
  readonly runId: string;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  readonly spawnProbe?: typeof spawnOwnedProviderProcess;
  readonly onStderr: (mode: "-envvars" | "-vmargs", stderr: string) => void;
}): Promise<{
  readonly command: string;
  readonly arguments: readonly string[];
  readonly environment: NodeJS.ProcessEnv;
}> => {
  const paths = options.platform === "win32" ? win32 : posix;
  const supportRoot = paths.dirname(options.analyzeHeadlessPath);
  const installRoot = paths.dirname(supportRoot);
  const command = paths.join(
    options.javaHome,
    "bin",
    options.platform === "win32" ? "java.exe" : "java",
  );
  const isolatedProperties = [
    `-Duser.home=${options.homeRoot}`,
    `-Djava.io.tmpdir=${options.tempRoot}`,
    // Ghidra's application properties take precedence over XDG/Windows env.
    // These follow release VM arguments so settings/cache/temp stay session-owned.
    `-Dapplication.settingsdir=${options.configRoot}`,
    `-Dapplication.cachedir=${options.cacheRoot}`,
    `-Dapplication.tempdir=${options.tempRoot}`,
  ];
  const supportArguments = [
    ...isolatedProperties,
    ...(options.platform === "win32" ? ["-XX:-UsePerfData"] : []),
    // Only identified HotSpot VMs have these unified-logging semantics. OpenJ9
    // uses different -Xlog behavior; missing VM identity must stay unknown.
    ...(/^(?:OpenJDK|Java HotSpot\(TM\)) (?:64-Bit )?(?:Server|Client|Zero) VM$/u.test(
      options.javaVmName ?? "",
    )
      ? ["-Xlog:disable", "-Xlog:all=warning:stderr"]
      : []),
    "-cp",
    paths.join(supportRoot, "LaunchSupport.jar"),
    "LaunchSupport",
    installRoot,
  ];
  const environment = {
    ...snapshotEnvironment(options.environment, options.platform),
  };
  const probe = async (mode: "-envvars" | "-vmargs") => {
    try {
      return await runOwnedCommand(
        {
          command,
          arguments: [...supportArguments, mode],
          runId: options.runId,
          expectedCommand: command,
          platform: options.platform,
          env: environment,
          hostEnvironment: {},
        },
        {
          timeoutMs: options.timeoutMs,
          diagnosticBytes: GHIDRA_LAUNCH_SUPPORT_OUTPUT_BYTES,
        },
        {
          ...(options.signal === undefined ? {} : { signal: options.signal }),
          ...(options.spawnProbe === undefined
            ? {}
            : { launcher: options.spawnProbe }),
        },
      );
    } catch (cause: unknown) {
      throw new GhidraLaunchSupportError(mode, cause);
    }
  };
  const configuredEnvironment = await probe("-envvars");
  options.onStderr("-envvars", configuredEnvironment.stderr.text);
  for (const line of configuredEnvironment.stdout.text.split(/\r?\n/u)) {
    if (line === "") continue;
    const separator = line.indexOf("=");
    const sourceKey = line.slice(0, separator);
    const key =
      options.platform === "win32" ? sourceKey.toUpperCase() : sourceKey;
    if (separator < 1 || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(key))
      throw new Error(
        `Invalid Ghidra LaunchSupport environment entry: ${line}`,
      );
    if ((environment[key] ?? "") === "")
      environment[key] = line.slice(separator + 1);
  }
  // The merged environment becomes the analysis JVM's environment, and the
  // JVM applies these options variables automatically. An injected
  // -Dos.arch/-Dos.name there selects an unvalidated native directory without
  // appearing in vmArguments, so reject the effective values as well.
  for (const key of [
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
  ] as const) {
    rejectJvmPlatformOverrides(jvmEnvironmentArguments(environment[key] ?? ""));
  }
  const configuredArguments = await probe("-vmargs");
  options.onStderr("-vmargs", configuredArguments.stderr.text);
  const vmArguments = configuredArguments.stdout.text
    .split(/\r?\n/u)
    .filter((line) => line !== "");
  if (
    vmArguments.some(
      (argument) => !argument.startsWith("-") || argument.includes("\0"),
    )
  )
    throw new Error("Invalid Ghidra LaunchSupport JVM argument");
  rejectJvmPlatformOverrides(vmArguments);
  return {
    command,
    environment,
    arguments: [
      ...vmArguments,
      ...(options.platform === "darwin" ? ["-Xdock:name=Ghidra-Headless"] : []),
      `-Xmx${environment.GHIDRA_HEADLESS_MAXMEM || environment.GHIDRA_MAXMEM || "2G"}`,
      "-XX:ParallelGCThreads=2",
      "-XX:CICompilerCount=2",
      "-Djava.awt.headless=true",
      ...isolatedProperties,
      ...(options.platform === "win32" ? ["-XX:-UsePerfData"] : []),
      "-showversion",
      "-cp",
      paths.join(
        installRoot,
        "Ghidra",
        "Framework",
        "Utility",
        "lib",
        "Utility.jar",
      ),
      "ghidra.Ghidra",
      "ghidra.app.util.headless.AnalyzeHeadless",
      ...options.arguments,
    ],
  };
};
