"""Policy engine smoke tests.

Copyright (c) 2026 NNSEC
SPDX-License-Identifier: AGPL-3.0-only
"""

import unittest
from pathlib import Path


class HealthApiTestCase(unittest.TestCase):
    def test_health_route_exists_in_source(self) -> None:
        source = Path(__file__).resolve().parents[1] / "app" / "main.py"
        content = source.read_text(encoding="utf-8")
        self.assertIn('@app.get("/healthz")', content)

    def test_decision_route_exists_in_source(self) -> None:
        source = Path(__file__).resolve().parents[1] / "app" / "main.py"
        content = source.read_text(encoding="utf-8")
        self.assertIn('@app.post("/v1/decision"', content)


if __name__ == "__main__":
    unittest.main()

