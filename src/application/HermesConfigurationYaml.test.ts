import { describe, expect, it } from "vitest";
import { parse } from "yaml";

import {
  editHermesConfigurationYaml,
  parseHermesConfigurationYaml,
} from "./HermesConfigurationYaml.js";

describe("Hermes configuration YAML", () => {
  it("writes an edited number from its new value", () => {
    expect(
      editHermesConfigurationYaml("mode: 0600\nmask: 0x1F\n", ["mode"], 420),
    ).toBe("mode: 0644\nmask: 0x1F\n");
  });

  it("accepts keys Hermes reads as distinct and rejects a repeated key", () => {
    expect(() =>
      parseHermesConfigurationYaml("0600: octal\n600: decimal\n"),
    ).not.toThrow();
    expect(() => parseHermesConfigurationYaml('a: 1\n"a": 2\n')).toThrow();
    expect(() => parseHermesConfigurationYaml("yes: 1\ntrue: 2\n")).toThrow();
    expect(() => parseHermesConfigurationYaml("no: 1\noff: 2\n")).toThrow();
  });

  it("honors YAML 1.2 directives while retaining Hermes timestamp semantics", () => {
    const original =
      "%YAML 1.2\n---\nnotify: on\ntimestamp: 2026-10-14T00:00:00.123456+08:00\n";
    const updated = editHermesConfigurationYaml(original, ["environment"], {
      SETTING: "off",
      DATE: "2026-10-14",
    });
    expect(updated.startsWith(original)).toBe(true);
    expect(parse(updated)).toMatchObject({
      notify: "on",
      environment: { SETTING: "off", DATE: "2026-10-14" },
    });
    expect(
      parseHermesConfigurationYaml("%YAML 1.2\n---\ndate: 2026-10-14\n"),
    ).toEqual({ date: new Date("2026-10-14") });
  });
});
