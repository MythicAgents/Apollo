// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

test("wireguard and ztna policy config exist", () => {
  const root = process.cwd();
  const wg = readFileSync(join(root, "config/wg0.conf"), "utf8");
  const rego = readFileSync(join(root, "config/ztna-authorizer.rego"), "utf8");
  assert.ok(wg.includes("Interface"));
  assert.ok(rego.includes("package"));
});
