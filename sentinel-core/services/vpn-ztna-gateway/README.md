# VPN/ZTNA Gateway PoC (WireGuard + SPIFFE)

<!--
Copyright (c) 2026 NNSEC Sentinel
SPDX-License-Identifier: AGPL-3.0-only
-->

This PoC documents a minimal gateway pattern:

1. Browser establishes WireGuard tunnel to nearest PoP.
2. Gateway validates SPIFFE ID minted for the authenticated session.
3. Route policy maps SPIFFE workload identity to app segments.

## Threat model note

- **Threat**: Stolen WireGuard private key.
- **Mitigation**: Session-bounded keys (24h max), SPIFFE SVID check on each access.
- **Residual risk**: Key abuse possible within active session TTL.

## Observability

- WireGuard interface metrics exported via node_exporter textfile collector.
- Envoy access logs include tenant_id and spiffe_id.

## Config files

- `config/wg0.conf`: sample WireGuard interface.
- `config/ztna-authorizer.rego`: sample policy for identity-aware allow rules.
