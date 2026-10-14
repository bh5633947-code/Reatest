import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

/**
 * Regression tests for https://github.com/morluto/rea/issues/2890: the
 * application graph must not invent a CommonJS `imports` edge for a `require`
 * call whose callee resolves to a lexically shadowing local binding. The
 * static findings are the producing boundary, so the tests assert on the
 * recovered `require` references directly.
 */
const requireSpecifiers = (source: string): readonly (string | null)[] =>
  analyzeJavaScriptStaticSource(source)
    .references.filter((reference) => reference.kind === "require")
    .map((reference) => reference.specifier);

const shadowedCases = [
  [
    "function parameter",
    `function run(require) {\n  return require("./ghost.cjs");\n}\nconsole.log(run(() => "local"));`,
  ],
  [
    "optional call with function parameter",
    `function run(require) {\n  return require?.("./ghost.cjs");\n}`,
  ],
  [
    "destructured parameter",
    `function load({ require }) { return require("./throwing.cjs"); }\nconsole.log(load({ require: () => "local" }));`,
  ],
  [
    "hoisted function declaration",
    `function load() {\n  console.log(require("./throwing.cjs"));\n  function require() { return "local"; }\n}\nload();`,
  ],
  [
    "catch binding",
    `try { throw () => "local"; }\ncatch (require) { console.log(require("./throwing.cjs")); }`,
  ],
  [
    "block-scoped binding",
    `{ const require = () => "local";\n  console.log(require("./throwing.cjs")); }`,
  ],
  [
    "initialized top-level var",
    `var require = () => "local";\nconsole.log(require("./throwing.cjs"));`,
  ],
  [
    "top-level let binding",
    `export {}; let require; require?.("./ghost.cjs");`,
  ],
  [
    "nested shadow inside a require-named bundle factory",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { function inner(require) { return require("./nested.cjs"); } } }]);`,
  ],
  [
    "factory loader parameter replaced by a hoisted function declaration",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { function require() { return "local"; } require("ghost"); } }]);`,
  ],
  [
    "factory loader parameter replaced by an initialized var redeclaration",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { var require = () => "local"; require("./ghost.cjs"); } }]);`,
  ],
  [
    "computed method key after a factory write",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { require = () => "local"; const obj = { [require("ghost")]() {} }; } }]);`,
  ],
  [
    "computed class method key after a factory write",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { require = () => "local"; class Routes { [require("ghost")]() {} } } }]);`,
  ],
  [
    "factory rest copy replaces the loader parameter",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { var {...require} = {}; require?.("ghost"); } }]);`,
  ],
  [
    "call after a createRequire alias is replaced",
    `import { createRequire } from "node:module";\nlet require = createRequire(import.meta.url);\nrequire = localLoader;\nrequire("./ghost.cjs");`,
  ],
  [
    "factory loader parameter reassigned before the call",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { require = () => "local"; require("./ghost.cjs"); } }]);`,
  ],
  [
    "write in an earlier instance field shadows a call in a later field",
    `var require;\nclass C {\n  first = (require = () => "local");\n  second = require("./ghost.cjs");\n}\nnew C();`,
  ],
  [
    "write and call in the same instance field",
    `var require;\nclass C {\n  first = (require = () => "local", require("./ghost.cjs"));\n}\nnew C();`,
  ],
  [
    "destructured missing property of createRequire",
    `import { createRequire } from "node:module";\nconst { missing: require } = createRequire(import.meta.url);\nrequire?.("./ghost.cjs");`,
  ],
  [
    "object-rest declaration",
    `var {...require} = {};\nrequire?.("./ghost.cjs");`,
  ],
  [
    "array-rest declaration",
    `var [...require] = [];\nrequire?.("./ghost.cjs");`,
  ],
  [
    "for-of write before the call in the loop body",
    `var require;\nfor (require of [() => "local"]) { require("./ghost.cjs"); }`,
  ],
  [
    "for-in write before the call in the loop body",
    `var require;\nfor (require in { a: 1 }) { require("./ghost.cjs"); }`,
  ],
  [
    "call after a for-of write",
    `var require;\nfor (require of [() => "local"]) {}\nrequire("./after.cjs");`,
  ],
  [
    "call before the createRequire establishing write invents no dependency",
    `import { createRequire } from "node:module";\nlet require;\nrequire?.("./ghost.cjs");\nrequire = createRequire(import.meta.url);`,
  ],
  [
    "call after a write in a static class field",
    `var require;\nclass C { static initialized = (require = () => "local"); }\nrequire("./ghost.cjs");`,
  ],
  [
    "call after a write in the same if branch",
    `var require;\nif (condition) { require = localLoader; require("./ghost.cjs"); }`,
  ],
  [
    "loader restored by a later createRequire write then shadowed again",
    `import { createRequire } from "node:module";\nlet require = () => "local";\nrequire = createRequire(import.meta.url);\nrequire = otherLoader;\nrequire("./ghost.cjs");`,
  ],
  [
    "conditional createRequire write invents no dependency",
    `import { createRequire } from "node:module";\nlet require = () => "local";\nif (condition) require = createRequire(import.meta.url);\nrequire("./ghost.cjs");`,
  ],
  [
    "var declaration initializer after the createRequire write shadows it",
    `import { createRequire } from "node:module";\nrequire = createRequire(import.meta.url);\nvar require = () => "local";\nrequire("./ghost.cjs");`,
  ],
];

const loaderCases = [
  [
    "ordinary unbound call",
    `const value = require("./real.cjs");`,
    ["./real.cjs"],
  ],
  [
    "optional unbound call",
    `const value = require?.("./real.cjs");`,
    ["./real.cjs"],
  ],
  [
    "uninitialized top-level var retains the wrapper loader",
    `var require;\nconsole.log(require("./loaded.cjs"));`,
    ["./loaded.cjs"],
  ],
  [
    "direct createRequire binding",
    `import { createRequire } from "node:module";\nconst require = createRequire(import.meta.url);\nconst value = require("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "createRequire alias keeps the call before a later write",
    `import { createRequire } from "node:module";\nlet require = createRequire(import.meta.url);\nrequire("./dep.cjs");\nrequire = localLoader;`,
    ["./dep.cjs"],
  ],
  [
    "loader restored by a later createRequire write after a local value",
    `import { createRequire } from "node:module";\nlet require = () => "local";\nrequire = createRequire(import.meta.url);\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "calls on either side of a restored createRequire write",
    `import { createRequire } from "node:module";\nlet require = createRequire(import.meta.url);\nrequire("./before.cjs");\nrequire = () => "local";\nrequire = createRequire(import.meta.url);\nrequire("./after.cjs");`,
    ["./before.cjs", "./after.cjs"],
  ],
  [
    "createRequire alias established by an assignment",
    `import { createRequire } from "node:module";\nvar require;\nrequire = createRequire(import.meta.url);\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "top-level call before a var declaration initializer",
    `require("./dep.cjs");\nvar require = localLoader;`,
    ["./dep.cjs"],
  ],
  [
    "createRequire binding behind erased TypeScript syntax",
    `import { createRequire } from "node:module";\nconst require = createRequire(import.meta.url) as NodeRequire;\nconst value = require("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "loader call before reassignment",
    `require?.("./dep");\nrequire = localLoader;`,
    ["./dep"],
  ],
  [
    "eager computed method key before reassignment",
    `const routes = { [require?.("./dep")]() {} };\nrequire = localLoader;`,
    ["./dep"],
  ],
  [
    "bundle factory whose loader parameter is named require",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { require("dep"); } }]);`,
    ["dep"],
  ],
  [
    "bundle factory loader call next to a nested shadow",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { require("dep"); function inner(require) { return require("./nested.cjs"); } } }]);`,
    ["dep"],
  ],
  [
    "factory loader parameter with an uninitialized var redeclaration",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { var require; require("dep"); } }]);`,
    ["dep"],
  ],
  [
    "factory loader parameter call before its reassignment",
    `globalThis.webpackChunkApp.push([[1], { entry(module, exports, require) { require("dep"); require = () => "local"; } }]);`,
    ["dep"],
  ],
  [
    "default-import createRequire binding",
    `import module from "node:module";\nconst require = module.createRequire(import.meta.url);\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "createRequire with fileURLToPath(import.meta.url)",
    `import { createRequire } from "node:module";\nimport { fileURLToPath } from "node:url";\nconst require = createRequire(fileURLToPath(import.meta.url));\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "namespace createRequire binding",
    `import * as module from "node:module";\nconst require = module.createRequire(import.meta.url);\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "call inside the right-hand side of its own reassignment",
    `var require; require = require("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "top-level call before a deferred write",
    `var require;\nfunction f() { require = localLoader; }\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "call before a for-of write",
    `var require;\nrequire("./before.cjs");\nfor (require of [() => "local"]) { require("./ghost.cjs"); }`,
    ["./before.cjs"],
  ],
  [
    "call before a for-in write",
    `var require;\nrequire("./before.cjs");\nfor (require in { a: 1 }) { require("./ghost.cjs"); }`,
    ["./before.cjs"],
  ],
  [
    "iterable call of a for-of loop sees the loader",
    `var require;\nfor (require of require("./iter.cjs")) { require("./ghost.cjs"); }`,
    ["./iter.cjs"],
  ],
  [
    "write inside if(false) does not hide the dependency",
    `var require;\nif (false) require = localLoader;\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "write inside a never-entered loop does not hide the dependency",
    `var require;\nwhile (false) { require = localLoader; }\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "write in a skipped if branch does not hide the dependency",
    `var require;\nif (condition) require = localLoader; else require = otherLoader;\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "write in an uninstantiated class field does not hide the dependency",
    `var require;\nclass C { value = (require = () => "local"); }\nrequire("./dep.cjs");`,
    ["./dep.cjs"],
  ],
  [
    "write in a later instance field does not hide an earlier field's call",
    `var require;\nclass C {\n  first = require("./dep.cjs");\n  second = (require = () => "local");\n}\nnew C();`,
    ["./dep.cjs"],
  ],
  [
    "instance field write does not hide a call in another class's field",
    `var require;\nclass A { first = (require = () => "local"); }\nclass B { second = require("./dep.cjs"); }\nnew A();\nnew B();`,
    ["./dep.cjs"],
  ],
  [
    "instance field write does not hide a call in a class method",
    `var require;\nclass C {\n  first = (require = () => "local");\n  m() { return require("./dep.cjs"); }\n}\nnew C().m();`,
    ["./dep.cjs"],
  ],
];

describe("lexically shadowed require calls", () => {
  it.each(shadowedCases)(
    "emits no require reference for a %s shadow",
    (_label, source) => {
      expect(requireSpecifiers(source)).toEqual([]);
    },
  );

  it.each(loaderCases)(
    "keeps the require reference for %s",
    (_label, source, expected) => {
      expect(requireSpecifiers(source)).toEqual(expected);
    },
  );

  it("keeps only the genuine call in a mixed file", () => {
    expect(
      requireSpecifiers(
        `console.log(require("./loaded.cjs"));\nfunction load(require) { return require("./throwing.cjs"); }\nconsole.log(load(() => "local"));`,
      ),
    ).toEqual(["./loaded.cjs"]);
  });

  it("keeps the loader call before a write but not the call after it", () => {
    expect(
      requireSpecifiers(
        `var require;\nrequire("./before.cjs");\nrequire = localLoader;\nrequire("./after.cjs");`,
      ),
    ).toEqual(["./before.cjs"]);
  });

  it("keeps the createRequire call before a later write but not the call after it", () => {
    expect(
      requireSpecifiers(
        `import { createRequire } from "node:module";\nlet require = createRequire(import.meta.url);\nrequire("./before.cjs");\nrequire = localLoader;\nrequire("./after.cjs");`,
      ),
    ).toEqual(["./before.cjs"]);
  });

  it("drops the call after a write in the same function body", () => {
    expect(
      requireSpecifiers(
        `var require;\nfunction f() { require = localLoader; return require("./x.cjs"); }\nf();`,
      ),
    ).toEqual([]);
  });
});
