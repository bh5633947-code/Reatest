import { createRequire } from "node:module";
import { isIP } from "node:net";
import { Ajv } from "ajv";
import { z } from "zod";
import { CaptureFormatError } from "./CaptureFormatError.js";
import { captureObject } from "./CaptureRedaction.js";

/** Validate using the unchanged, pinned upstream HAR 1.2 draft-06 schemas. */
export const createHarValidator = (): ((value: unknown) => void) => {
  const require = createRequire(import.meta.url);
  const schemas = z
    .record(z.string(), z.record(z.string(), z.unknown()))
    .parse(require("har-schema"));
  const ajv = new Ajv({ strict: false, allErrors: false, ownProperties: true });
  ajv.addMetaSchema(require("ajv/dist/refs/json-schema-draft-06.json"));
  const plugin: unknown = require("ajv-formats");
  if (typeof plugin !== "function")
    throw new Error("Pinned AJV formats plugin is unavailable");
  plugin(ajv);
  for (const schema of Object.values(schemas)) ajv.addSchema(schema);
  const validate = ajv.getSchema("har.json#");
  if (validate === undefined)
    throw new Error("Pinned HAR root schema is unavailable");
  return (value) => {
    allowObservedProducerRepresentations(value);
    if (!validate(value)) {
      const error = validate.errors?.[0];
      // AJV messages name the violated constraint, such as the missing
      // property, without restating any captured value.
      throw new CaptureFormatError(
        "format",
        error === undefined
          ? "HAR schema validation failed: unknown constraint."
          : `HAR schema validation failed: ${error.keyword} (${error.message ?? "no detail"}).`,
        error?.instancePath ?? "",
      );
    }
  };
};

/** Adapt only the disposable validation copy, preserving original reported spellings. */
const allowObservedProducerRepresentations = (value: unknown): void => {
  if (!captureObject(value) || !captureObject(value.log)) return;
  const log = value.log;
  if (!captureObject(log.creator) || !Array.isArray(log.entries)) return;
  const mitmproxy =
    log.creator.name === "mitmproxy" && log.creator.version === "12.2.3";
  const playwright =
    log.creator.name === "Playwright" && log.creator.version === "1.58.2";
  if (!mitmproxy && !playwright) return;
  for (const entry of log.entries) {
    const candidate: unknown = entry;
    if (!captureObject(candidate)) continue;
    // Playwright 1.58.2 forwards Chromium's remoteIPAddress spelling to HAR.
    // Recognize an IPv6 literal, not URL authority syntax, ports or zone IDs.
    const address = candidate.serverIPAddress;
    if (
      playwright &&
      typeof address === "string" &&
      address.startsWith("[") &&
      address.endsWith("]") &&
      isIP(address.slice(1, -1)) === 6
    )
      candidate.serverIPAddress = address.slice(1, -1);
    if (!mitmproxy) continue;
    const request = candidate.request;
    if (!captureObject(request)) continue;
    const body = request.postData;
    if (captureObject(body) && body.text === null) delete body.text;
  }
};
