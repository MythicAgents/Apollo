# Sentinel Core PoC (Deliverable 15)

This directory contains runnable proof-of-concept modules for NNSEC Sentinel:

1. Chromium macOS screenshot protection patch example
2. Policy engine (FastAPI + OPA)
3. Admin dashboard skeleton (Next.js 15)
4. Telemetry ingestion skeleton (Kafka -> Flink -> OpenSearch)
5. Device posture agent (Go + osquery integration pattern)
6. Session recording library (rrweb + encrypted upload)
7. VPN/ZTNA gateway PoC (WireGuard + identity-aware policy)
8. Password vault PoC (E2EE)
9. NL-to-policy compiler utility
10. Local `docker-compose.yml`
11. `Makefile` for DX
12. Per-module README files with architecture and threat notes

## Quick start

```bash
cd sentinel-core
make up
```

## Notes

- This is a baseline scaffold for architecture validation and integration sequencing.
- Production hardening (authN/Z depth, secret management, HA, SLOs) is defined in Deliverables 2-14 and implemented incrementally.
