// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("session recorder exports startRecorder", () => {
  const source = readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");
  assert.ok(source.includes("export function startRecorder"), "startRecorder export missing");
  assert.ok(source.includes("aes-256-gcm"), "expected encryption primitive not found");
});

