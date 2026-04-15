# Deliverable 13: Go-to-Market, Commercial Strategy, and Legal

## 1. Scope
This deliverable defines how NNSEC Sentinel will be packaged, priced, sold, and defended legally as an open-core cybersecurity platform. It includes pricing and packaging strategy, ICP/channel model, launch sequencing, support SLAs, and legal foundations (EULA/DPA/subprocessors/export control/trademark posture).

## 2. Open-Core Split

| Layer | License | Included Capabilities | Rationale |
|---|---|---|---|
| Sentinel Community Core | AGPLv3 | Base policy engine, browser management primitives, baseline telemetry ingestion, local dashboard starter | Ecosystem trust + adoption funnel |
| Sentinel Commercial Add-ons | Commercial EULA | Advanced DLP, session recording, UEBA, dark-web monitoring, AI analyst, MSSP console | Revenue capture for high-value controls |
| OEM/White-label MSP Pack | Commercial + OEM terms | Multi-tenant branding, partner API, reseller billing hooks | NNSEC channel leverage |

### ADR-13-01: AGPL core with commercial enterprise modules
- Context: Need rapid adoption and differentiator monetization without giving away expensive IP.
- Options:
  1. Closed-source everything.
  2. Open-core AGPL + commercial.
  3. Permissive OSS + hosted SaaS-only value.
- Decision: Option 2.
- Consequences:
  - Positive: Community contribution path, transparent trust posture, monetization.
  - Negative: License compliance overhead and enforcement effort.
  - Neutral: Requires clean module boundary.
- Rejected:
  - Option 1 reduces trust and slows ecosystem.
  - Option 3 risks competitive commoditization.
- Revisit trigger: If >30% of support burden is from non-paying AGPL users with minimal conversion.

## 3. Pricing Tiers and Feature Matrix

All prices USD, annual commitment, indicative launch pricing.

| Tier | Target | Price / user / month | Min Seats | Core Features |
|---|---|---:|---:|---|
| Community | Dev/security teams | $0 | 1 | Core policy + browser controls (self-host) |
| Team | SMB | $12 | 25 | Managed browser controls, base threat blocking, basic reports |
| Business | Mid-market regulated | $24 | 100 | DLP L1–L4, posture, session recording selective, SIEM/SOAR integrations |
| Enterprise | Regulated large org | $39 | 500 | Full DLP L1–L6, UEBA, legal hold, advanced compliance workspace, optional blockchain anchor |
| MSSP | Service providers | $22 effective blended + platform fee | 1,000 pooled | Multi-tenant master console, white-label, tenant billing APIs |

### 3.1 Competitor Pricing Comparison (Estimated/Public Mix)

| Vendor | Public Pricing Signal | Effective Range | Notes |
|---|---|---|---|
| Prisma Access Browser | Quote-based | $35–$70 | Often bundled with Prisma stack |
| Island | Quote-based | $40–$80 | Premium enterprise packaging |
| Talon (historical) | Quote-based | $30–$60 | Now integrated into Palo Alto |
| NordLayer | Public starting plans | $8–$20 | Not full secure-browser parity |
| Zscaler (ZIA/ZPA) | Quote-based | $20–$60+ | Depends on modules |
| Cloudflare One | Public enterprise mix | $15–$45 | Add-ons influence materially |
| Surf Security | Quote-based | $25–$50 | Secure browser specific |

## 4. ICP and Segmentation

| Segment | Profile | Key Pain | Purchase Driver | Sales Motion |
|---|---|---|---|---|
| Primary | Regulated fintech (100–5,000 users) | DLP + BYOD + audit burden | Consolidation and PCI/ISO evidence | Direct, technical champion + CISO |
| Secondary | MSSPs serving SME | Tool sprawl and margin pressure | White-label multi-tenant control plane | Channel + partner enablement |
| Tertiary | Dev-heavy technology orgs | GenAI data leakage | Fast policy-as-code + browser control | Product-led assisted |

## 5. Channel Strategy

| Channel | Role | KPI | Enablement Asset |
|---|---|---|---|
| Direct enterprise | Anchor logos (Bamboo + peers) | ARR / logo | Security architecture workshop |
| MSSP partner network | Scaled distribution | Tenants onboarded / quarter | White-label deployment kit |
| GACA-certified partners | Compliance trust channel | Certified deployments | GACA control mapping package |

## 6. Launch Sequence

| Milestone | Target Month | Exit Criteria |
|---|---:|---|
| Internal alpha (Bamboo) | 4 | 150 users, p95 policy eval <10 ms, <2% critical workflow breakage |
| Private beta (3–5 partners) | 7 | 3 paying design partners, >90% deployment automation |
| Public beta | 10 | Multi-region availability + documented SLO attainment |
| GA | 13 | Security review closure, support readiness, SOC2 Type I completion |

## 7. Support and Success Model

| Plan | SLA | Channels | TAM/CSM |
|---|---|---|---|
| Business | P1 1h response, P2 4h | Portal + email | Shared CSM |
| Enterprise | P1 30m response, P2 2h | Portal + email + Slack connect | Dedicated CSM |
| MSSP | P1 30m response multi-tenant | Portal + partner Slack/Teams | Partner success manager |

## 8. Legal Architecture

### 8.1 Required agreements
| Document | Scope | Owner |
|---|---|---|
| EULA | Commercial software terms, limits, warranties | Legal counsel |
| DPA | Controller/processor obligations | Privacy counsel |
| Subprocessor list | Transparency and update process | Security + legal |
| SLA annex | Availability and service credits | Support operations |
| OEM terms | MSSP resale and branding rights | Channel legal |

### 8.2 Export-control stance
- Chromium + strong crypto subject to EAR; classify distribution according to U.S. ECCN 5D002/5D992 patterns (jurisdiction-specific review required before broad export).
- Maintain denied-party screening for enterprise deals and provide geo-restriction controls.

### 8.3 Trademark analysis and fallback names
- “Sentinel” is crowded in security classes. Parallel trademark screening must include:
  - NNSEC Sentinel
  - NNSEC Vanguard
  - NNSEC Aegis
  - NNSEC Bastion
- Revisit naming decision before public beta if conflict risk > medium in target jurisdictions (UAE, EU, US, UK).

## 9. Unit Economics and Financial Model

### 9.1 Target metrics
| Metric | Target |
|---|---:|
| Gross margin (year 2) | >= 70% |
| Net retention (year 2) | >= 115% |
| CAC payback | < 14 months |
| LTV:CAC | >= 3.0 |

### 9.2 Indicative economics example (Business tier)
- ARPU: $24 x 12 = $288/user/year.
- Direct COGS allocation target: <= $86/user/year.
- Gross margin target: >= 70%.

## 10. Risk Register (Commercial/Legal)

| Risk | L | I | Score | Mitigation | Residual | Owner |
|---|---:|---:|---:|---|---|---|
| Trademark conflict delays launch | 3 | 4 | 12 | Early legal search, reserve fallback marks | Medium | Legal lead |
| Long enterprise procurement cycles | 4 | 3 | 12 | Design-partner reference + MSSP channel acceleration | Medium | CRO |
| Price pressure in bundles | 3 | 4 | 12 | Differentiate on integrated browser-native control depth | Medium | Product marketing |
| Export-control complexity | 2 | 4 | 8 | External counsel, region-based controls | Low-medium | Legal/compliance |
| High support burden in beta | 3 | 3 | 9 | SRE runbooks, launch cohort limits | Medium | Support lead |

## 11. Assumptions & Open Questions

### Assumptions
- NNSEC can support direct enterprise sales and partner channel simultaneously.
- Buyer persona includes CISO + IT operations with budget authority.
- Security/legal counsel retained before public beta.

### Open Questions
- Final trademark clearance status by jurisdiction.
- Preferred billing operations stack beyond Stripe (e.g., taxation automation).
- Whether to offer sovereign-region data residency at GA or post-GA.

