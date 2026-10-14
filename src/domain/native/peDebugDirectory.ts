import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(0xffffffff);
const range = z.strictObject({ offset: uint, bytes: uint });

/** Named IMAGE_DEBUG_TYPE values; unknown numeric types remain `other`. */
export const PE_DEBUG_TYPE_NAMES = [
  "unknown",
  "coff",
  "codeview",
  "fpo",
  "misc",
  "exception",
  "fixup",
  "omap_to_src",
  "omap_from_src",
  "borland",
  "reserved10",
  "clsid",
  "vc_feature",
  "pogo",
  "iltcg",
  "mpx",
  "repro",
  "ex_dllcharacteristics",
  "other",
] as const;

const PE_DEBUG_TYPE_BY_ID: Readonly<Record<number, PeDebugTypeName>> = {
  0: "unknown",
  1: "coff",
  2: "codeview",
  3: "fpo",
  4: "misc",
  5: "exception",
  6: "fixup",
  7: "omap_to_src",
  8: "omap_from_src",
  9: "borland",
  10: "reserved10",
  11: "clsid",
  12: "vc_feature",
  13: "pogo",
  14: "iltcg",
  15: "mpx",
  16: "repro",
  20: "ex_dllcharacteristics",
};

export type PeDebugTypeName = (typeof PE_DEBUG_TYPE_NAMES)[number];

/** Map a PE debug-directory type DWORD to a named kind without guessing unknowns. */
export const peDebugTypeName = (type: number): PeDebugTypeName =>
  PE_DEBUG_TYPE_BY_ID[type] ?? "other";

const codeViewRsdsSchema = z.strictObject({
  kind: z.literal("codeview_rsds"),
  pdb_path: z.string().min(1),
  pdb_file_name: z.string().min(1),
  guid: z.string().min(1),
  age: uint,
});

const codeViewNb10Schema = z.strictObject({
  kind: z.literal("codeview_nb10"),
  pdb_path: z.string().min(1),
  pdb_file_name: z.string().min(1),
  age: uint,
});

const codeViewUnparsedSchema = z.strictObject({
  kind: z.literal("codeview_unparsed"),
  magic: z.string(),
});

const reproSchema = z.strictObject({
  kind: z.literal("repro"),
  hash_hex: z.string().regex(/^(?:[0-9a-f]{2})+$/u),
});

const exDllCharacteristicsSchema = z.strictObject({
  kind: z.literal("ex_dllcharacteristics"),
  characteristics: uint,
});

const miscSchema = z.strictObject({
  kind: z.literal("misc"),
  data_type: uint,
  unicode: z.boolean(),
  path: z.string().nullable(),
});

const opaqueSchema = z.strictObject({
  kind: z.literal("opaque"),
});

export const peDebugPayloadSchema = z.discriminatedUnion("kind", [
  codeViewRsdsSchema,
  codeViewNb10Schema,
  codeViewUnparsedSchema,
  reproSchema,
  exDllCharacteristicsSchema,
  miscSchema,
  opaqueSchema,
]);

export const peDebugDirectoryEntrySchema = z.strictObject({
  index: uint,
  type: uint,
  type_name: z.enum(PE_DEBUG_TYPE_NAMES),
  characteristics: uint,
  timestamp: uint,
  major_version: uint,
  minor_version: uint,
  directory_location: range,
  address_of_raw_data: uint,
  pointer_to_raw_data: uint,
  payload: z.strictObject({
    location: range,
    sha256: digestSchema,
    decoded: peDebugPayloadSchema,
  }),
});

/** Complete bounded inspection of one caller-selected PE image, without execution. */
export const inspectPeDebugDirectoryInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to a PE image",
  ),
  max_file_bytes: z
    .number()
    .int()
    .min(64)
    .max(536870912)
    .default(67108864)
    .describe("Maximum stable artifact bytes to read (default 64 MiB)"),
  max_entries: z
    .number()
    .int()
    .min(1)
    .max(4096)
    .default(256)
    .describe(
      "Maximum IMAGE_DEBUG_DIRECTORY entries to examine; exceeding the budget fails without partial success",
    ),
});

/** Observed PE debug-directory inventory; missing directories stay empty, not assumed absent from the build. */
export const peDebugDirectorySchema = z
  .strictObject({
    artifact: z.strictObject({
      path: z.string().min(1),
      sha256: digestSchema,
      bytes: uint,
    }),
    format: z.enum(["pe32", "pe32-plus"]),
    machine: uint,
    directory: z
      .strictObject({
        rva: uint,
        location: range,
        data_directory_location: range,
      })
      .nullable(),
    entries: z.array(peDebugDirectoryEntrySchema),
    coverage: z.strictObject({
      status: z.literal("complete"),
      entries: uint,
    }),
    limitations: z.array(z.string().min(1)).min(1),
  })
  .superRefine((report, context) => {
    const inside = (item: { offset: number; bytes: number }): boolean =>
      item.offset <= report.artifact.bytes &&
      item.bytes <= report.artifact.bytes - item.offset;
    if (report.coverage.entries !== report.entries.length) {
      context.addIssue({
        code: "custom",
        path: ["coverage", "entries"],
        message: "Coverage entry count disagrees with the retained inventory.",
      });
    }
    if (report.directory === null && report.entries.length > 0) {
      context.addIssue({
        code: "custom",
        path: ["entries"],
        message: "Debug entries require a present data directory.",
      });
    }
    if (report.directory !== null && !inside(report.directory.location)) {
      context.addIssue({
        code: "custom",
        path: ["directory", "location"],
        message: "Debug directory range leaves the selected artifact.",
      });
    }
    if (
      report.directory !== null &&
      !inside(report.directory.data_directory_location)
    ) {
      context.addIssue({
        code: "custom",
        path: ["directory", "data_directory_location"],
        message: "Debug data-directory header leaves the selected artifact.",
      });
    }
    for (const [index, entry] of report.entries.entries()) {
      if (entry.index !== index) {
        context.addIssue({
          code: "custom",
          path: ["entries", index, "index"],
          message: "Debug entry index is not its inventory position.",
        });
      }
      if (!inside(entry.directory_location)) {
        context.addIssue({
          code: "custom",
          path: ["entries", index, "directory_location"],
          message: "Debug directory entry leaves the selected artifact.",
        });
      }
      if (!inside(entry.payload.location)) {
        context.addIssue({
          code: "custom",
          path: ["entries", index, "payload", "location"],
          message: "Debug payload range leaves the selected artifact.",
        });
      }
    }
  });

export type PeDebugDirectory = z.infer<typeof peDebugDirectorySchema>;
export type PeDebugPayload = z.infer<typeof peDebugPayloadSchema>;
export type InspectPeDebugDirectoryInput = z.infer<
  typeof inspectPeDebugDirectoryInputSchema
>;
