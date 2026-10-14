import { expect, it } from "vitest";
import { WebNetworkApiSurfaceAccumulator } from "../../domain/analysisView/WebNetworkApiSurfaceAccumulator.js";
import { decodeSazHttp } from "./SazHttp.js";
import { projectSazRecord } from "./SazProjection.js";

it.each([
  {
    ending: "\r\n",
    value: "\r\n\tapplication/json",
    types: ["application/json"],
  },
  { ending: "\n", value: "\n application/json", types: ["application/json"] },
  { ending: "\r\n", value: "\n application/json", types: [] },
  { ending: "\r\n", value: "\r\n \n application/json", types: [] },
  { ending: "\n", value: "\r application/json", types: [] },
  { ending: "\r\n", value: " application/json;\n charset=utf-8", types: [] },
])(
  "uses only parsed continuations for $ending framing and $value",
  ({ ending, value, types }) => {
    const response = decodeSazHttp(
      Buffer.from(
        `HTTP/1.1 200 OK${ending}Content-Type:${value}${ending}${ending}{}`,
      ),
      false,
    );
    const projected = projectSazRecord(
      {
        request: { method: "GET", url: "https://api.test/items/1" },
        response,
      },
      [],
    );
    expect(projected.reported).toMatchObject({
      response: { headers: [{ name: "Content-Type", value }] },
    });
    const accumulator = new WebNetworkApiSurfaceAccumulator();
    const result = accumulator.add(
      {
        ordinal: 0,
        location: { kind: "archive-members", members: ["raw/1_s.txt"] },
        ...projected,
        limitations: [],
      },
      "saz",
    );
    if (!result.ok) throw result.error;
    expect(accumulator.page(0, 1).groups[0]?.content_types).toEqual(types);
  },
);

it("redacts both spellings of folded credentials and explicitly sensitive headers", () => {
  const value = "\r\n\tapplication/json";
  const response = decodeSazHttp(
    Buffer.from(
      `HTTP/1.1 200 OK\r\nAuthorization: Bearer\r\n secret\r\nContent-Type:${value}\r\n\r\n`,
    ),
    false,
  );
  const projected = projectSazRecord({ response }, [value]);
  expect(projected.reported).toMatchObject({
    response: {
      headers: [
        { name: "Authorization", value: null, value_unfolded: null },
        { name: "Content-Type", value: null, value_unfolded: null },
      ],
    },
  });
  expect(JSON.stringify(projected)).not.toContain("Bearer");
  expect(JSON.stringify(projected)).not.toContain("secret");
  expect(JSON.stringify(projected)).not.toContain("application/json");
});
