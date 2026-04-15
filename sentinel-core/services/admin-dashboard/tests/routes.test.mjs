// Copyright (c) 2026 NNSEC Sentinel
// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const requiredRoutes = [
  "app/page.tsx",
  "app/(auth)/login/page.tsx",
  "app/(app)/tenants/page.tsx",
  "app/(app)/devices/page.tsx",
];

test("required route files exist", () => {
  for (const route of requiredRoutes) {
    const file = join(root, route);
    assert.equal(existsSync(file), true, `missing ${route}`);
  }
});

