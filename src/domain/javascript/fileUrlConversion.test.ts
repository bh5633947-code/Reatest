import { expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

it("decodes a literal file URL before projecting an Electron preload", () => {
  const analysis = analyzeJavaScriptStaticSource(`
    import { fileURLToPath } from "node:url";
    import { BrowserWindow } from "electron";
    new BrowserWindow({ webPreferences: {
      preload: fileURLToPath("file:///app/preload%20file.js")
    } });
  `);
  expect(analysis.electron.browser_windows[0]).toMatchObject({
    preload_path: "/app/preload file.js",
    preload_resolution_context: "filesystem-expression",
  });
  expect(
    analysis.role_paths.find(({ role }) => role === "preload"),
  ).toMatchObject({
    path: "/app/preload file.js",
    resolution_context: "filesystem-expression",
  });
});

it("preserves source-relative and unknown file URL conversion controls", () => {
  const analysis = analyzeJavaScriptStaticSource(`
    import { fileURLToPath } from "node:url";
    import { BrowserWindow } from "electron";
    new BrowserWindow({ webPreferences: { preload: fileURLToPath(new URL("./preload.js", import.meta.url)) } });
    new BrowserWindow({ webPreferences: { preload: fileURLToPath(selectedUrl) } });
  `);
  expect(analysis.electron.browser_windows[0]?.preload_path).toBe(
    "./preload.js",
  );
  expect(analysis.electron.browser_windows[1]?.preload_path).toBeNull();
});

it.each([
  "file:///app/preload.js",
  "file://localhost/app/preload%20file.js",
  "file:///app/%E2%9C%93.js",
  "file:///app/preload.js?query=1#fragment",
])("projects %s through all static path consumers", (url) => {
  const expression = `fileURLToPath(${JSON.stringify(url)})`;
  const analysis = analyzeJavaScriptStaticSource(`
    import { fileURLToPath } from "node:url";
    import { BrowserWindow, utilityProcess } from "electron";
    new BrowserWindow({ webPreferences: { preload: ${expression} } });
    utilityProcess.fork(${expression});
  `);
  const expected = fileURLToPath(url, { windows: false });
  expect(analysis.electron.browser_windows[0]).toMatchObject({
    preload_path: expected,
    preload_resolution_context: "filesystem-expression",
  });
  expect(analysis.electron.utility_processes[0]).toMatchObject({
    module_path: expected,
    module_resolution_context: "filesystem-expression",
  });
  expect(analysis.role_paths).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        path: expected,
        resolution_context: "filesystem-expression",
      }),
    ]),
  );
});

it.each([
  'fileURLToPath("https://example.invalid/preload.js")',
  'fileURLToPath("/app/preload.js")',
  'fileURLToPath("file:///app/%2Fpreload.js")',
  'fileURLToPath("file:///app/%")',
  'fileURLToPath("file:///C:/app/preload.js")',
  'fileURLToPath("file:///C%3A/app/preload.js")',
  'fileURLToPath("file:///%43:/app/preload.js")',
  'fileURLToPath("file://remote/share/preload.js")',
  'fileURLToPath("file:///app/preload.js", { windows: selectedPlatform })',
])("keeps invalid or platform-dependent %s unresolved", (expression) => {
  const analysis = analyzeJavaScriptStaticSource(`
    import { fileURLToPath } from "node:url";
    import { BrowserWindow } from "electron";
    new BrowserWindow({ webPreferences: { preload: ${expression} } });
  `);
  expect(analysis.electron.browser_windows[0]?.preload_path).toBeNull();
  expect(analysis.role_paths).toEqual([]);
});
