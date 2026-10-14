import {
  isScalar,
  parseDocument,
  Document,
  Schema,
  type ParsedNode,
  type ScalarTag,
  type Tags,
} from "yaml";

const SOURCE_SCALAR_TAGS = new Set([
  "tag:yaml.org,2002:int",
  "tag:yaml.org,2002:float",
  "tag:yaml.org,2002:timestamp",
]);

// Hermes's ruamel reader resolves dates even with an explicit YAML 1.2 directive.
const timestampTag = new Schema({ schema: "yaml-1.1" }).tags.find(
  ({ tag }) => tag === "tag:yaml.org,2002:timestamp",
)!;

const sameScalarValue = (left: unknown, right: unknown): boolean =>
  Object.is(left, right) ||
  (left instanceof Date &&
    right instanceof Date &&
    left.getTime() === right.getTime());

/**
 * Write a parsed scalar with its source spelling while that spelling still
 * reads as the node's value. Hermes reads config.yaml as YAML 1.1 with exact
 * integers, so re-printing a JavaScript number changes what it reads: a
 * Discord channel ID loses its low digits, `0600` (octal) becomes `600`, and
 * `0.0000001` becomes `1e-7`, which YAML 1.1 does not define as a float.
 * Timestamp source also retains precision and offsets absent from JS Dates.
 */
const keepScalarSource = (tag: Tags[number]): Tags[number] => {
  if (typeof tag === "string" || tag.collection !== undefined) return tag;
  const { stringify } = tag;
  if (!SOURCE_SCALAR_TAGS.has(tag.tag) || stringify === undefined) return tag;
  return {
    ...tag,
    stringify: (item, context, ...rest) => {
      const { source } = item;
      if (source === undefined) return stringify(item, context, ...rest);
      const reader = context.doc.schema.tags.find(
        (candidate): candidate is ScalarTag =>
          candidate.default === true && candidate.test?.test(source) === true,
      );
      const read = reader?.resolve(
        source,
        () => undefined,
        context.doc.options,
      );
      return sameScalarValue(isScalar(read) ? read.value : read, item.value)
        ? source
        : stringify(item, context, ...rest);
    },
  };
};

const HERMES_YAML_OPTIONS = {
  // Hermes defaults to YAML 1.1; an explicit document directive still wins.
  // Use the same schema to interpret existing values and quote new strings.
  version: "1.1" as const,
  customTags: (tags: Tags) =>
    (tags.some((tag) => typeof tag !== "string" && tag.tag === timestampTag.tag)
      ? tags
      : [...tags, timestampTag]
    ).map(keepScalarSource),
  // Hermes keeps integers exact, so IDs that round to one double, or `0600`
  // and `600`, are distinct keys.
  uniqueKeys: (a: ParsedNode, b: ParsedNode) =>
    a === b ||
    (isScalar(a) &&
      isScalar(b) &&
      sameScalarValue(a.value, b.value) &&
      // Numeric/timestamp source distinguishes precision lost by JS values.
      // Boolean and string spellings still denote the same semantic key.
      (!(typeof a.value === "number" || a.value instanceof Date) ||
        a.source === b.source)),
};

/** Create a Hermes config using the same scalar rules as edits and readback. */
export const stringifyHermesConfigurationYaml = (
  document: Record<string, unknown>,
): string =>
  new Document(document, HERMES_YAML_OPTIONS).toString({ lineWidth: 0 });

// A comment-only document has no root; a bare marker has an unwritten null
// scalar. Explicit null values, tags and anchors remain actual values.
const isEmptyYamlRoot = (root: Document["contents"]): boolean =>
  root === null ||
  (isScalar(root) &&
    root.value === null &&
    root.source === "" &&
    root.tag === undefined &&
    root.anchor === undefined);

const parseHermesDocument = (text: string) => {
  const document = parseDocument(text, HERMES_YAML_OPTIONS);
  const error = document.errors[0];
  if (error !== undefined) throw error;
  return document;
};

/** Parse a Hermes `config.yaml`, preserving the distinction between no root and explicit null. */
export const parseHermesConfigurationYaml = (text: string): unknown => {
  const document = parseHermesDocument(text);
  return isEmptyYamlRoot(document.contents) ? {} : document.toJS();
};

/** Set or delete one value in a Hermes `config.yaml`, keeping the rest as written. */
export const editHermesConfigurationYaml = (
  text: string,
  path: readonly string[],
  value: unknown,
): string => {
  // A plain Document, so a bare `---` root can be replaced by a new map.
  const document: Document = parseHermesDocument(text);
  const root = document.contents;
  if (isEmptyYamlRoot(root)) {
    const map = document.createNode({});
    if (isScalar(root))
      map.commentBefore = [root.commentBefore, root.comment]
        .filter((comment) => comment !== undefined)
        .join("\n");
    document.contents = map;
  }
  if (value === undefined) document.deleteIn(path);
  else {
    // setIn's implicit JS Map parents serialize as !!omap in YAML 1.1.
    // Config settings are ordinary mappings, including absent server tables.
    for (let length = 1; length < path.length; length++) {
      const parent = path.slice(0, length);
      if (!document.hasIn(parent))
        document.setIn(parent, document.createNode({}));
    }
    document.setIn(path, value);
  }
  // Editing REA must not reflow unrelated user prompts or other YAML scalars.
  return document.toString({ lineWidth: 0 });
};
