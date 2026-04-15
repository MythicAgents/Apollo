# Telemetry Ingestion PoC (Kafka -> Flink -> OpenSearch)

## Purpose
Demonstrates ingestion of browser telemetry events through Kafka, stream processing in Flink SQL, and indexing into OpenSearch.

## Components
- `schemas/browser_event.avsc`: canonical event schema.
- `kafka/topics.md`: topic and retention design.
- `flink/job.py`: enrichment transform scaffold.
- `tests/test_job.py`: unit tests for enrichment behavior.

## Threat Model Notes
- Spoofed producer events mitigated with mTLS/SASL in production.
- Poison-pill payloads mitigated with schema registry compatibility and dead-letter topics.

## Observability Hooks
- Kafka lag metrics (consumer group lag).
- Flink checkpoint duration and restart counts.
- OpenSearch indexing failure count.
