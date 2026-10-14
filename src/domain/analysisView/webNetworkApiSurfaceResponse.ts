import { z } from "zod";
import type { JsonValue } from "../jsonValue.js";

const responseSchema = z.object({
  response: z.object({
    status: z.unknown().optional(),
    content: z.unknown().optional(),
    headers: z.unknown().optional(),
  }),
});
const contentSchema = z.object({ mimeType: z.unknown().optional() });
const headerSchema = z.object({
  name: z.string(),
  value: z.unknown(),
  value_unfolded: z.unknown().optional(),
});
const MEDIA_TYPE_ESSENCE =
  /^[A-Za-z0-9!#$%&'*+.^_`|~-]+\/[A-Za-z0-9!#$%&'*+.^_`|~-]+$/u;

/** Derive a MIME only after the caller admits the original header's text cost. */
export const apiSurfaceMediaType = (field: string): string | null => {
  // Remaining line breaks were not accepted by the owning HTTP parser.
  if (/[\r\n]/u.test(field)) return null;
  const separator = field.indexOf(";");
  let start = 0;
  let end = separator < 0 ? field.length : separator;
  // HTTP OWS is SP/HTAB. Scan from both ends so malformed internal runs of
  // whitespace cannot cause repeated trailing-regex searches.
  while (start < end && (field[start] === " " || field[start] === "\t"))
    start += 1;
  while (end > start && (field[end - 1] === " " || field[end - 1] === "\t"))
    end -= 1;
  const essence = field.slice(start, end);
  // Validate ASCII tokens before case folding can turn Unicode into ASCII.
  return MEDIA_TYPE_ESSENCE.test(essence) ? essence.toLowerCase() : null;
};

/** A duplicate or unreadable header cannot establish a single Content-Type. */
const sazContentType = (
  headers: unknown,
): { readonly value: string; readonly sourceLength: number } | undefined => {
  if (!Array.isArray(headers)) return undefined;
  let found = false;
  let value:
    | { readonly value: string; readonly sourceLength: number }
    | undefined;
  for (const header of headers) {
    const parsed = headerSchema.safeParse(header);
    if (!parsed.success) return undefined;
    // Bound case folding to the one field name this projection consumes.
    if (
      parsed.data.name.length !== 12 ||
      parsed.data.name.toLowerCase() !== "content-type"
    )
      continue;
    if (found) return undefined;
    found = true;
    const raw = parsed.data.value;
    if (typeof raw !== "string") return undefined;
    const unfolded = parsed.data.value_unfolded;
    if (unfolded !== undefined && typeof unfolded !== "string")
      return undefined;
    value = { value: unfolded ?? raw, sourceLength: raw.length };
  }
  return value;
};

/** Interpret retained format facts; never reparse HTTP bytes or inspect bodies. */
export const apiSurfaceResponse = (
  reported: JsonValue,
  format: "har" | "saz",
): {
  readonly status: number | null;
  readonly mime: string;
  readonly mimeSourceLength: number;
} => {
  const parsed = responseSchema.safeParse(reported);
  if (!parsed.success) return { status: null, mime: "", mimeSourceLength: 0 };
  const response = parsed.data.response;
  const status =
    format === "saz"
      ? typeof response.status === "string" &&
        /^[0-9]{3}$/u.test(response.status)
        ? Number(response.status)
        : null
      : typeof response.status === "number"
        ? response.status
        : null;
  const content = contentSchema.safeParse(response.content);
  const saz = format === "saz" ? sazContentType(response.headers) : undefined;
  const mime =
    format === "saz"
      ? saz?.value
      : content.success
        ? content.data.mimeType
        : undefined;
  return {
    status: status === 0 ? null : status,
    mime: typeof mime === "string" ? mime : "",
    mimeSourceLength: saz?.sourceLength ?? 0,
  };
};
