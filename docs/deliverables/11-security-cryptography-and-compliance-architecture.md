# Deliverable 11 - Security, Cryptography, and Compliance Architecture

## Scope Statement

This deliverable defines NNSEC Sentinel's security architecture, cryptographic standards, key and secret management, zero-trust workload identity, comprehensive compliance mappings, vulnerability and incident management, and software supply-chain controls. It includes explicit framework-control mappings and evidence artifacts for regulated enterprise operation.

## 11.1 Enterprise Security Requirements (Enumerated, Non-Vague)

Sentinel "enterprise-grade" means all of the following are implemented and measurable:

1. Tenant-isolated cryptographic domains with per-tenant key material.
2. mTLS authentication for all east-west service calls.
3. Tamper-evident immutable audit trail with verifiable integrity proofs.
4. Deterministic, testable policy decisions (<10 ms p95) with signed policy bundles.
5. 24x7 vulnerability management with severity-based SLA and automated ticket routing.
6. Evidence-on-demand for PCI DSS v4.0, ISO 27001:2022, SOC 2 Type II, GDPR, UAE PDPL.
7. Reproducible build provenance and signed release artifacts (SLSA L3 path).
8. Incident response runbooks with timeline reconstruction under 30 minutes from alert.
9. Browser-bound IdP access where unmanaged browsers fail before reaching the IdP login flow.

## 11.2 Cryptographic Architecture Inventory

### 11.2.1 Protocol and Cipher Policy

| Layer | Policy | Notes |
|---|---|---|
| External API traffic | TLS 1.3 only | TLS 1.2 temporary exception for legacy SIEM integration endpoint; sunset by GA+2 quarters |
| Service-to-service | mTLS with SPIFFE SVID | X.509 SVID rotation every 24h |
| Data at rest (object) | AES-256-GCM | Envelope-encrypted object key per object/session |
| Data at rest (database) | AES-256 (storage) + column crypto | pgcrypto for sensitive columns |
| Low-latency streaming channels | ChaCha20-Poly1305 fallback | For clients without AES-NI performance |
| Signatures (modern) | Ed25519 | Policy bundle signatures, offline license tokens |
| KEX | X25519 | Default key exchange |
| Compatibility | ECDSA P-256, RSA-3072 | Legacy enterprise endpoints |

### 11.2.2 Key Hierarchy

```text
Root of Trust (CloudHSM-backed tenant root keys)
  -> Service KEKs (per service, per tenant, rotated 90 days)
    -> DEKs (per object/session/event batch, rotated per write policy)
      -> In-memory ephemeral keys (process lifetime only)
```

### 11.2.3 Post-Quantum Roadmap

| Version Track | PQC State | Compatibility |
|---|---|---|
| v1 | Classical crypto only, PQC-ready abstractions | N/A |
| v2 | Hybrid handshake pilot: X25519 + ML-KEM | Select APIs and control channels |
| v3 | ML-KEM and ML-DSA production options with policy toggle | Regulated tenant opt-in then default |

NIST references: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA). Revisit trigger: broad vendor support and FIPS-validated module availability in target runtimes.

## 11.3 ADRs (Security and Cryptography)

### ADR-SEC-11-000: Four-layer browser-bound IdP enforcement

**Context:** Sentinel must prove that SSO login requests originate from enrolled Sentinel browsers on attested devices, not generic browsers.

**Options considered:**  
1) Conditional access only (source IP + user-agent)  
2) mTLS only  
3) Layered model: mTLS + signed attestation + gateway + conditional access

**Decision:** Use the layered model. mTLS and signed attestation are mandatory; conditional access is auxiliary; gateway enforces checks before forwarding to IdP.

**Consequences:**  
- Positive: Strong resistance to unmanaged-browser access and token replay.  
- Negative: Additional integration complexity (gateway + IdP plugin/policy updates).  
- Neutral: Introduces one additional high-availability component in auth path.

**Alternatives rejected:**  
- Conditional-access-only is trivially bypassable via spoofed user-agent and proxied traffic.  
- mTLS-only does not capture posture state and has weaker replay semantics.

**Revisit trigger:** If false-reject rate exceeds 1% p95 over 7 days or mobile-platform constraints require temporary fallback mode.

### ADR-SEC-11-001: Managed HSM vs self-hosted HSM

**Context:** Tenant key segregation and high-assurance cryptographic operations are required for PCI and enterprise procurement.

**Options considered:**  
1) AWS CloudHSM primary  
2) Self-hosted SoftHSM/PKCS#11 on Kubernetes  
3) Third-party external key management SaaS

**Decision:** Use AWS CloudHSM as primary for production key roots; YubiHSM2 for offline MSP signing and disaster-recovery escrow workflows.

**Consequences:**  
- Positive: Hardware-backed key controls, auditability, enterprise trust.  
- Negative: Higher recurring cost, cloud lock-in risk.  
- Neutral: Requires key ceremony SOP and operator training.

**Alternatives rejected:**  
- Self-hosted SoftHSM lacks strong hardware assurances for high-sensitivity tiers.  
- External KMS SaaS may introduce jurisdiction and contractual complexity for UAE/PCI constraints.

**Revisit trigger:** Multi-cloud demand exceeding 30% of ARR or non-AWS sovereign cloud requirements.

### ADR-SEC-11-002: Vault choice for secrets

**Context:** Sentinel services need dynamic credentials and secret rotation across cloud and potentially air-gapped deployment modes.

**Options considered:**  
1) AWS Secrets Manager only  
2) HashiCorp Vault only  
3) Hybrid approach

**Decision:** Hybrid: AWS Secrets Manager for AWS-native deployments; Vault-supported mode for hybrid/on-prem/air-gapped customers.

**Consequences:**  
- Positive: Flexibility across deployment topologies.  
- Negative: Dual operational models and testing burden.  
- Neutral: Shared secret schema is mandatory.

**Alternatives rejected:** Single-vendor model not compatible with stated multi-cloud and on-prem requirements.

**Revisit trigger:** Adoption data indicates >85% homogeneous cloud deployments for four consecutive quarters.

## 11.4 Compliance Mapping Tables (Representative Coverage)

### 11.4.1 ISO 27001:2022 (Representative subset, full catalog in compliance workspace seed)

| Control ID | Sentinel Feature | Evidence Artifact | Status |
|---|---|---|---|
| A.5.15 Access control | Policy engine + RBAC + conditional access | Policy export, RBAC matrix, access review logs | Fully |
| A.5.16 Identity management | Identity broker + SCIM provisioning | SCIM sync audit logs, onboarding/offboarding records | Fully |
| A.5.23 Information security in supplier relationships | Third-party feed risk register | Vendor assessments, subprocessor inventory | Partially |
| A.8.16 Monitoring activities | Session telemetry, UEBA, SIEM integration | Monitoring dashboards, alert records | Fully |
| A.8.23 Web filtering | DNS filtering + URL policy engine | Blocklist diffs, policy assignment logs | Fully |
| A.8.28 Secure coding | SDLC controls, SAST/DAST gates | CI logs, code review evidence, vuln SLAs | Contributes-to |

### 11.4.2 PCI DSS v4.0 (Core requirements)

| PCI Req | Sentinel Feature | Evidence Artifact | Status |
|---|---|---|---|
| 4 - Protect cardholder data with strong cryptography in transit | TLS 1.3, mTLS internal | TLS config snapshots, scanner output | Fully |
| 6 - Develop secure systems/software | CI security gates + dependency policy | Pipeline logs, SBOM, exception register | Contributes-to |
| 7 - Restrict access by need to know | RBAC + scoped policy + JIT | Access review and policy audit trail | Fully |
| 8 - Identify users and authenticate access | SSO/MFA/Device posture | IdP logs, conditional access reports | Fully |
| 10 - Log and monitor all access | Immutable audit logs, SIEM feed | Hash-chain verification reports | Fully |
| 11 - Test security regularly | Quarterly pen tests + continuous scanning | Pen test reports, remediation trackers | Fully |
| 12 - Security governance | IR plans, policy governance workflow | Policy docs, tabletop records | Contributes-to |

### 11.4.3 SOC 2 Type II (TSC)

| TSC | Sentinel Controls | Evidence | Status |
|---|---|---|---|
| Security | IAM, encryption, monitoring, secure SDLC | SOC evidence package export | Fully |
| Availability | Multi-region DR, SLO/error budgets | SLO dashboards and incident postmortems | Fully |
| Processing Integrity | Deterministic policy evaluation and tests | Policy test results, change controls | Fully |
| Confidentiality | DLP, encryption, tenant isolation | Data classification matrix, access logs | Fully |
| Privacy | DSR workflows, minimization, retention | DSR tickets and deletion proofs | Partially (org process dependent) |

### 11.4.4 GDPR / UAE PDPL / HIPAA / NIS2 / Cyber Essentials Plus

| Framework Article/Control | Sentinel Mapping | Evidence | Status |
|---|---|---|---|
| GDPR Art. 25 (privacy by design) | Default minimization, redaction, retention defaults | System design docs, config baselines | Contributes-to |
| GDPR Art. 30 (records of processing) | Processing inventory in compliance workspace | Data processing register export | Partially |
| GDPR Art. 32 (security of processing) | Encryption + access control + monitoring | Crypto config and access logs | Fully |
| UAE PDPL (data subject rights) | Export/delete/rectify APIs + workflow | DSR audit reports | Partially |
| HIPAA 164.312 (technical safeguards) | Access control, transmission security, audit controls | Audit trail and access reports | Contributes-to |
| NIS2 (risk management) | Risk register, incident workflow | Risk dashboard and IR records | Contributes-to |
| Cyber Essentials Plus controls | Secure config, malware protection, updates | Hardening baselines and vuln scans | Contributes-to |

### 11.4.5 Browser-Bound IdP Control Mapping

| Control | Sentinel Mechanism | Evidence Artifact | Status |
|---|---|---|---|
| ISO 27001:2022 A.5.16 Identity management | Device-bound mTLS cert + attestation key registry | cert issuance logs, key enrollment records | Fully |
| ISO 27001:2022 A.8.16 Monitoring activities | gateway deny reason telemetry + replay alerts | dashboard snapshots, SIEM alerts | Fully |
| PCI DSS v4.0 Req 8 (Identify users/authenticate) | pre-IdP attestation checks with posture threshold | auth decision logs, policy config export | Fully |
| SOC 2 CC6 Logical Access | layered access gate before IdP token issuance | gateway audit logs + IdP conditional policy snapshot | Fully |
| GDPR Art. 32 Security of processing | replay resistance and non-exportable key usage | threat model, architecture docs, test evidence | Contributes-to |

## 11.5 Threat Model (STRIDE across cryptographic and compliance surfaces)

| Threat | Category | Impact | Mitigation | Residual |
|---|---|---|---|---|
| Stolen service identity cert used for API impersonation | Spoofing | Unauthorized calls | SPIFFE cert TTL 24h, revocation, mTLS authz, behavior anomaly alerts | Low |
| Altered audit logs before export | Tampering | Compliance failure | Append-only Merkle chain, object lock, external hash anchors | Low |
| Admin denies policy change action | Repudiation | Investigation gap | Signed commits, immutable change audit, approval workflow | Low |
| Key metadata leakage through verbose logs | Information disclosure | Key lifecycle intel leak | Structured logging denylist, secret scanners in CI, runtime log scrubbing | Medium |
| KMS outage blocks new session key generation | DoS | User impact | Local sealed key cache with TTL, fallback region KMS, degrade mode | Medium |
| Abuse of compliance export endpoint | Elevation of privilege | Bulk sensitive data exfil | Scoped roles, export watermarking, rate-limits, approval for mass export | Medium |
| Replay of `X-Sentinel-Attestation` header | Replay | Unauthorized login reuse | nonce cache + timestamp freshness <=60s + device-cert subject binding | Low |
| Unmanaged browser attempts direct IdP login | Spoofing | Policy bypass attempt | mTLS mandatory endpoint + gateway deny-before-IdP | Low |

## 11.6 Vulnerability Management Program

| Severity | Target SLA (triage) | Target SLA (fix in prod) | Escalation |
|---|---|---|---|
| Critical (CVSS >=9 or exploited) | 2 hours | 24 hours | CISO + on-call engineering manager |
| High | 24 hours | 7 days | Security lead + service owner |
| Medium | 3 business days | 30 days | Product security + team lead |
| Low | 10 business days | 90 days | Backlog governance |

EPSS is used as an override to raise priority when exploitation probability is high even at medium CVSS.

## 11.7 Pen-Test, Bug Bounty, and Incident Response

### 11.7.1 Penetration Testing

- Cadence: quarterly external pen test, monthly internal red-team-style abuse tests on high-risk flows.
- Providers: CREST-certified firms for external; rotating provider model annually.
- Scope includes browser client, admin APIs, tenant isolation, update channel, and policy compiler.
- Fix SLAs follow section 11.6.

### 11.7.2 Bug Bounty

| Program Element | Plan |
|---|---|
| Platform | HackerOne or Bugcrowd |
| Initial scope | Admin API, tenant isolation, browser policy bypass, update service |
| Reward bands | Low $300-$800, Medium $800-$2,500, High $2,500-$8,000, Critical $8,000-$25,000 |
| Safe harbor | Standard legal safe-harbor language, no customer data access allowed |

### 11.7.3 Incident Response

| Phase | Target Time |
|---|---|
| Detection to triage | <15 minutes for P1 alerts |
| Triage to containment | <60 minutes |
| Containment to eradication plan | <4 hours |
| Regulatory notification determination | <24 hours |

Tabletop exercises: monthly for security engineering, quarterly cross-functional.

## 11.8 Supply Chain Security Architecture

| Control | Implementation |
|---|---|
| SLSA level | Path to SLSA L3 by GA via hardened build, provenance attestations |
| Provenance signatures | Sigstore Fulcio/Rekor for containers and binary metadata |
| SBOM | CycloneDX + SPDX generated every release |
| Dependency governance | Pinning and allowlist for critical dependencies, transitive-risk policy |
| Artifact signing | Cosign for OCI, GPG/platform signing for binaries |
| Verification gates | Admission control denies unsigned/unprovenanced artifacts |

## 11.9 Performance and Resilience Budgets for Security Controls

| Control Path | Budget |
|---|---|
| mTLS handshake overhead (intra-region) | <15 ms p95 |
| Attestation verification at gateway | <25 ms p95 |
| Audit append write latency | <30 ms p95 |
| Merkle chunking batch finalization | <2 s every 1,000 events |
| Key unwrap per session | <20 ms p95 |
| Compliance evidence query response | <2 s p95 for 7-day window |

Measurement plan: OpenTelemetry spans tagged by control-path; dashboards with SLO burn alerts.

## 11.10 Risk Register (Security and Compliance)

| Risk | L | I | Score | Mitigation | Owner | Residual |
|---|---:|---:|---:|---|---|---|
| Cross-tenant data leak via query bug | 2 | 5 | 10 | RLS tests, tenant isolation fuzzing, canary tenants | Platform Security Lead | Medium |
| Delayed patching in Chromium fork | 3 | 5 | 15 | Weekly sync cadence, emergency patch lane | Browser Platform Lead | Medium |
| HSM/KMS misconfiguration | 2 | 4 | 8 | IaC policy checks, dual-control key ceremony | Security Engineering Manager | Low |
| Insufficient evidence quality for audits | 3 | 4 | 12 | Automated evidence capture with owner assignment | Compliance Program Manager | Medium |
| Legal/regional transfer misalignment | 2 | 5 | 10 | Data residency options, DPA clauses, legal review gates | Legal Counsel + CISO | Medium |

## 11.11 Assumptions & Open Questions

### Assumptions

1. Enterprise Anthropic API contract allows incident-triage workflows with strict retention controls.
2. Regulated customers accept CloudHSM-backed architecture when key jurisdiction is documented.
3. Audit evidence export format supports both machine and auditor-readable bundles.

### Open Questions

1. Which blockchain network will be approved for optional audit-anchor in enterprise contracts?
2. Will certain GCC-region customers require sovereign cloud variants on day one?
3. Should Sentinel provide built-in DPA templates per jurisdiction or customer-supplied only?

Deliverable 11 of 15 complete. Ready for Deliverable 12 - proceed?
