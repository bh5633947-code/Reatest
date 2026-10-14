import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

describe("Electron exact preference keys", () => {
  it("does not confuse a wrapped empty preference key with an unknown preload override", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const { BrowserWindow } = require("electron");
      new BrowserWindow({ webPreferences: { preload: "./kept.js", ["" as const]: true } });
    `);
    expect(analysis.parse_status).toBe("complete");
    expect(analysis.electron.browser_windows[0]).toMatchObject({
      preload_path: "./kept.js",
      web_preferences: [
        {
          name: "",
          value: { status: "literal", value: true, expression: null },
        },
        {
          name: "preload",
          value: { status: "literal", value: "./kept.js", expression: null },
        },
      ],
    });
  });

  it("retains computed literal preference names, including empty and numeric keys", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const { BrowserWindow } = require("electron");
      new BrowserWindow({ webPreferences: {
        ["sandbox"]: true, ["preload"]: "./preload.js", [""]: false, [1]: "one"
      } });
    `);
    expect(analysis.parse_status).toBe("complete");
    expect(analysis.electron.browser_windows[0]).toMatchObject({
      preload_path: "./preload.js",
      web_preferences: [
        {
          name: "",
          value: { status: "literal", value: false, expression: null },
        },
        {
          name: "1",
          value: { status: "literal", value: "one", expression: null },
        },
        {
          name: "preload",
          value: { status: "literal", value: "./preload.js", expression: null },
        },
        {
          name: "sandbox",
          value: { status: "literal", value: true, expression: null },
        },
      ],
    });
  });

  it("keeps an unresolved computed preference key and its preload override unknown", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const { BrowserWindow } = require("electron");
      new BrowserWindow({ webPreferences: {
        ["preload"]: "./maybe.js", [getKey()]: true
      } });
    `);
    expect(analysis.parse_status).toBe("partial");
    expect(analysis.electron.browser_windows[0]).toMatchObject({
      preload_path: null,
    });
    expect(analysis.electron.browser_windows[0]?.web_preferences).toEqual(
      expect.arrayContaining([
        {
          name: "preload",
          value: { status: "literal", value: "./maybe.js", expression: null },
        },
        {
          name: expect.stringMatching(/^\[dynamic@/u),
          value: expect.objectContaining({ status: "dynamic", value: null }),
        },
      ]),
    );
  });
});

describe("Electron option evidence", () => {
  it("keeps the final explicit preload and service name with unrelated keys", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const { BrowserWindow, utilityProcess } = require("electron");
      new BrowserWindow({ webPreferences: { preload: "./kept.js", sandbox: true }, title: "App" });
      utilityProcess.fork("./worker.js", [], { serviceName: "kept", cwd: "/app" });
    `);

    expect(analysis.parse_status).toBe("complete");
    expect(analysis.electron.browser_windows[0]).toMatchObject({
      preload_path: "./kept.js",
      preload_resolution_context: "module-specifier",
      web_preferences: [
        { name: "preload", value: { status: "literal", value: "./kept.js" } },
        { name: "sandbox", value: { status: "literal", value: true } },
      ],
    });
    expect(analysis.electron.utility_processes[0]).toMatchObject({
      module_path: "./worker.js",
      service_name: "kept",
    });
  });

  it.each([
    ["for initializer", 'for (var electron = require("electron"); false;) {}'],
    ["do body", 'do { var electron = require("electron"); } while (false);'],
  ])(
    "recovers Electron bindings initialized unconditionally in a %s",
    (_name, declaration) => {
      const analysis = analyzeJavaScriptStaticSource(
        `${declaration} new electron.BrowserWindow({webPreferences:{preload:"./preload.js"}});`,
      );
      expect(analysis.parse_error_count).toBe(0);
      expect(analysis.electron.browser_windows).toMatchObject([
        { preload_path: "./preload.js" },
      ]);
    },
  );

  it.each([
    'for (; false;) { var electron = require("electron"); }',
    'while (false) { var electron = require("electron"); }',
    'if (flag) { for (var electron = require("electron"); false;) {} }',
  ])(
    "keeps conditionally skipped loop declarations unresolved: %s",
    (declaration) => {
      const analysis = analyzeJavaScriptStaticSource(
        `${declaration} new electron.BrowserWindow({});`,
      );
      expect(analysis.electron.browser_windows).toEqual([]);
    },
  );

  it("does not read an audio or video preload attribute as a preload script", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      jsx("audio", { controls: true, preload: "metadata", src });
      (0, React.createElement)(\`video\`, { preload: "auto" });
      jsx("webview", { preload: "./guest.js" });
      const options = { preload: "./preload.js" };
    `);

    expect(analysis.role_paths.map(({ path }) => path)).toEqual([
      "./guest.js",
      "./preload.js",
    ]);
  });

  it("keeps values unknown when a later computed key can override them", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const { BrowserWindow, utilityProcess } = require("electron");
      new BrowserWindow({ webPreferences: { preload: "./maybe.js" }, [key]: null });
      utilityProcess.fork("./worker.js", [], { serviceName: "maybe", [key]: null });
    `);

    expect(analysis.parse_status).toBe("partial");
    expect(analysis.parse_error_count).toBe(0);
    expect(analysis.limitations.join(" ")).toContain("remain unknown");
    expect(analysis.electron.browser_windows[0]).toMatchObject({
      preload_path: null,
      preload_resolution_context: null,
      web_preferences_status: "dynamic",
      web_preferences: [],
    });
    expect(analysis.electron.utility_processes[0]).toMatchObject({
      module_path: "./worker.js",
      service_name: null,
    });
  });

  it("keeps recovered templates with invalid escapes dynamic", () => {
    const source = [
      'const { BrowserWindow } = require("electron");',
      "new BrowserWindow({ webPreferences: { sandbox: `",
      String.raw`\unicode`,
      "` } });",
    ].join("");
    const analysis = analyzeJavaScriptStaticSource(source);

    expect(analysis.parse_status).toBe("partial");
    expect(analysis.parse_error_count).toBe(1);
    expect(
      analysis.electron.browser_windows[0]?.web_preferences,
    ).toContainEqual(
      expect.objectContaining({
        name: "sandbox",
        value: expect.objectContaining({ status: "dynamic", value: null }),
      }),
    );
  });
});
