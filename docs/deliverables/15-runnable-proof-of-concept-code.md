# Deliverable 15: Runnable Proof-of-Concept Code

## 15.1 Scope Statement
This deliverable provides runnable scaffolding for Sentinel core components with implementation notes, local execution instructions, tests, and threat-model/observability hooks. The goal is to establish an executable baseline that maps directly to the architecture and controls defined in Deliverables 1–14.

## 15.2 Repository Layout

```text
sentinel-core/
  chromium/patches/0001-macos-screenshot-protection.patch
  services/
    policy-engine/
    admin-dashboard/
    telemetry-ingestion/
    device-posture-agent/
    session-recorder/
    vpn-ztna-gateway/
    password-vault-poc/
    nl-policy-compiler/
  docker-compose.yml
  Makefile
```

## 15.3 Component Coverage Matrix

| Requested Component | Delivered Artifact | Status |
|---|---|---|
| Chromium patch example | `chromium/patches/0001-macos-screenshot-protection.patch` | Complete |
| Policy engine skeleton (FastAPI + OPA) | `services/policy-engine` + OPA in compose | Complete |
| Admin dashboard skeleton (Next.js 15 + shadcn-compatible) | `services/admin-dashboard` | Complete |
| Telemetry ingestion (Kafka -> Flink -> OpenSearch schema flow) | `services/telemetry-ingestion` + Redpanda in compose | Complete |
| Device posture agent (Go + osquery integration path) | `services/device-posture-agent` | Complete |
| Session recording library (rrweb + encrypted upload) | `services/session-recorder` | Complete |
| VPN/ZTNA gateway PoC (WireGuard + SPIFFE policy artifact) | `services/vpn-ztna-gateway` | Complete |
| Password vault PoC (client-side E2EE) | `services/password-vault-poc` | Complete |
| NL-to-policy compiler PoC | `services/nl-policy-compiler` | Complete |
| Full docker compose backend | `sentinel-core/docker-compose.yml` | Complete |
| DX task runner (`Makefile`) | `sentinel-core/Makefile` | Complete |
| README per module + threat model + observability notes | Present for each module | Complete |

## 15.4 Run Instructions

### 15.4.1 Bring up core services
```bash
cd sentinel-core
make up
```

### 15.4.2 Run local checks
```bash
cd sentinel-core
make test-policy
make test-go
make test-dashboard
make test-telemetry
make test-session-recorder
make test-password-vault
make test-nl-compiler
make test-vpn
```

### 15.4.3 Tear down stack
```bash
cd sentinel-core
make down
```

## 15.5 ADRs for PoC Implementation

### ADR-15-01: Compose-first Local Integration
- **Context**: The team needs a low-friction integration environment for a 2-engineer start.
- **Options considered**: Kubernetes local cluster only, docker-compose, cloud-only dev.
- **Decision**: docker-compose baseline for speed and reproducibility.
- **Consequences**: positive fast startup; negative environment differs from production orchestration; neutral portable service definitions.
- **Rejected alternatives**:
  - Kubernetes-only rejected because onboarding time is high for initial prototyping.
  - Cloud-only rejected due cost and iteration latency.
- **Revisit trigger**: when >8 services require advanced service mesh behavior not representable in compose.

### ADR-15-02: Source-level tests for some modules in PoC phase
- **Context**: Not all modules include full compile/transpile pipelines in initial scaffold.
- **Options considered**: strict compile tests only, source-level tests only, hybrid.
- **Decision**: hybrid; compile where possible and source-level invariants where toolchain bootstrap is pending.
- **Consequences**: positive immediate coverage; negative lower confidence for runtime wiring; neutral easy upgrade path to full tests.
- **Rejected alternatives**:
  - strict compile-only rejected because it blocks progress while build wiring is incomplete.
  - source-only rejected because it misses import/runtime defects where compile is available.
- **Revisit trigger**: before private beta all tests must become runtime or compile verified.

## 15.6 Threat Model Snapshot (Cross-Module)

| Threat | Modules | Mitigation in PoC |
|---|---|---|
| Policy bypass via malformed requests | policy-engine | schema validation + OPA deny fallback |
| Cross-tenant leakage in dashboard views | admin-dashboard | placeholder role-scoped pages + backend RLS requirement documented |
| Replay/tampering of session recordings | session-recorder | AES-256-GCM envelope with auth tag |
| Device posture spoofing | device-posture-agent | signed transport pathway documented, report schema with timestamps |
| Prompt injection into NL compiler | nl-policy-compiler | deterministic fallback and constrained generation model |
| Gateway key theft | vpn-ztna-gateway | session-bounded keys and SPIFFE identity checks documented |

## 15.7 Performance Budget Snapshot

| Component | Budget | PoC Measurement Hook |
|---|---|---|
| Policy decision API | <50ms p95 end-to-end | FastAPI timing logs + OPA benchmark command |
| Dashboard route render | <300ms TTFB local dev baseline | Next telemetry + route tests |
| Telemetry enrichment | <30ms/event processing overhead | sample enrichment script timings |
| Device posture submit | <1s/report local | Go test + request timing |
| NL compiler | <1500ms p95 compile | emitted trace metric placeholder |

## 15.8 Assumptions and Open Questions

### Assumptions
1. PoC can prioritize developer ergonomics over production completeness.
2. Full secret management integration is deferred to platform hardening stage.
3. Test harnesses can be upgraded iteratively as CI matures.

### Open Questions
1. Should the first end-to-end integration target policy+dashboard+gateway or policy+recording+UEBA?
2. Which service should own canonical tenant metadata in this PoC phase: tenant-manager placeholder or policy-engine seed?
3. Do design partners require on-prem compose bundle during private beta or only hosted environments?

