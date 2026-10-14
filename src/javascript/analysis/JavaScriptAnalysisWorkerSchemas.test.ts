import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "../../domain/javascript/javascriptStaticAnalysis.js";
import { javaScriptWorkerStaticAnalysisSchema } from "./JavaScriptAnalysisWorkerSchemas.js";

it("admits candidate endpoint interpretations through the worker schema", () => {
  const facts = analyzeJavaScriptStaticSource(
    'client.post("session"); fetch("/literal");',
  );
  const parsed = javaScriptWorkerStaticAnalysisSchema.parse(
    JSON.parse(JSON.stringify(facts)) as unknown,
  );
  const endpoint = (value: string) =>
    parsed.endpoints.find((item) => item.value === value);
  expect(endpoint("session")).toMatchObject({ interpretation: "candidate" });
  expect(endpoint("/literal")).toBeDefined();
  // An observed literal stays without the key rather than carrying undefined.
  expect(endpoint("/literal")).not.toHaveProperty("interpretation");
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
