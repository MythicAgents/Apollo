"""Telemetry enrichment tests.

SPDX-License-Identifier: AGPL-3.0-only
"""

import unittest

from flink.job import enrich


class EnrichTests(unittest.TestCase):
    def test_enrich_adds_pipeline_fields(self) -> None:
        payload = {"event_id": "evt-1", "tenant_id": "tenant-a"}
        result = enrich(payload)
        self.assertEqual(result["pipeline_version"], "0.1.0")
        self.assertIn("ingested_at", result)


if __name__ == "__main__":
    unittest.main()

