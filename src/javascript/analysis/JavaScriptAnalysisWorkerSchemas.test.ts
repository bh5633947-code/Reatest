import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "../../domain/javascript/javascriptStaticAnalysis.js";
import { javaScriptWorkerStaticAnalysisSchema } from "./JavaScriptAnalysisWorkerSchemas.js";

it("preserves endpoint interpretation through the worker boundary", () => {
  const facts = analyzeJavaScriptStaticSource(
    "app.get('setting', handler); fetch('/api');",
  );
  const parsed = javaScriptWorkerStaticAnalysisSchema.parse(
    JSON.parse(JSON.stringify(facts)) as unknown,
  );
  const candidate = parsed.endpoints.find(
    ({ mechanism }) => mechanism === "call:app.get",
  );
  expect(candidate).toMatchObject({
    kind: "network",
    value: "setting",
    interpretation: "candidate",
  });
  const network = parsed.endpoints.find(
    ({ mechanism }) => mechanism === "call:fetch",
  );
  expect(network).toMatchObject({ kind: "network", value: "/api" });
  expect(network).not.toHaveProperty("interpretation");
  expect(
    javaScriptWorkerStaticAnalysisSchema.safeParse({
      ...parsed,
      endpoints: parsed.endpoints.map((endpoint) => ({
        ...endpoint,
        interpretation: "literal",
      })),
    }).success,
  ).toBe(false);
});

it("versions fingerprints through the worker schema and rejects v1", () => {
  const facts =
    analyzeJavaScriptStaticSource(`globalThis.webpackChunkApp.push([[1], {
    17(module, exports) { const key = selectKey(); exports.read = value[key]; }
  }]);`);
  expect(facts.bundler_registrations[0]?.modules[0]).toMatchObject({
    structural_fingerprint_algorithm: "babel-ast-v2",
    structural_fingerprint_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
  });
  expect(
    javaScriptWorkerStaticAnalysisSchema.safeParse(
      JSON.parse(JSON.stringify(facts)) as unknown,
    ).success,
  ).toBe(true);
  const old = {
    ...facts,
    bundler_registrations: facts.bundler_registrations.map((registration) => ({
      ...registration,
      modules: registration.modules.map((module) => ({
        ...module,
        structural_fingerprint_algorithm: "babel-ast-v1",
      })),
    })),
  };
  expect(javaScriptWorkerStaticAnalysisSchema.safeParse(old).success).toBe(
    false,
  );
});
