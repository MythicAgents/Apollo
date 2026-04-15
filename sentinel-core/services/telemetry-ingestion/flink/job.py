#!/usr/bin/env python3
# Copyright (c) 2026 NNSEC Sentinel
# SPDX-License-Identifier: AGPL-3.0-only
"""
Sentinel telemetry enrichment job placeholder.
This script demonstrates schema-aware event handling before indexing.
"""

import json
from datetime import datetime, timezone


def enrich(event: dict) -> dict:
    event["pipeline_version"] = "0.1.0"
    event["ingested_at"] = datetime.now(timezone.utc).isoformat()
    return event


def main() -> None:
    sample = {
        "event_id": "evt-1",
        "tenant_id": "tenant-bamboo",
        "user_id": "user-100",
        "device_id": "dev-1",
        "event_type": "policy_violation",
        "severity": "high",
        "timestamp": "2026-04-15T10:00:00Z",
        "attributes": {"policy": "block-public-upload"},
    }
    print(json.dumps(enrich(sample), indent=2))


if __name__ == "__main__":
    main()
