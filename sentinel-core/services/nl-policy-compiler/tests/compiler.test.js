// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("compiler source retains deterministic fallback mapping", () => {
  const source = readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");
  assert.ok(source.includes("contains(") || source.includes("includes("));
  assert.ok(source.includes("Fallback policy generated"));
});

