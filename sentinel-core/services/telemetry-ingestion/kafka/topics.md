# Sentinel Telemetry Topics

## Topics
- `sentinel.browser.events.raw` (input)
- `sentinel.browser.events.enriched` (output)
- `sentinel.alerts` (derived)

## Partitioning strategy
- Key by `tenant_id:user_id` for per-user ordering.
- 24 partitions for raw events in PoC, scale to 192 in production.

## Retention
- Raw: 7 days
- Enriched: 30 days
- Alerts: 90 days

## Threat-model note
- Enforce mTLS + SASL SCRAM between producers and brokers.
- Topic ACLs scoped by service account.
