// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("vault source includes encrypt and decrypt functions", () => {
  const source = readFileSync(new URL("../src/vault.ts", import.meta.url), "utf8");
  assert.ok(source.includes("export function encryptSecret"));
  assert.ok(source.includes("export function decryptSecret"));
  assert.ok(source.includes("aes-256-gcm"));
});

