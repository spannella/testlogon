import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

describe("messaging draft analytics schema", () => {
  it("is metadata-only and forbids draft text payloads", () => {
    const schemaPath = path.resolve(process.cwd(), "../docs/messaging-drafts-event-schema.json");
    const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

    expect(schema.additionalProperties).toBe(false);
    expect(schema.properties.text).toBeUndefined();
    expect(schema.properties).toHaveProperty("event");
    expect(schema.properties).toHaveProperty("outcome");
    expect(schema.properties).toHaveProperty("source");
    expect(schema.properties).toHaveProperty("conversation_id_present");
    expect(schema.properties).toHaveProperty("at_ms");
  });
});
