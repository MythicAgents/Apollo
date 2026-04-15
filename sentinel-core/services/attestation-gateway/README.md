# Sentinel Attestation Gateway PoC

This service enforces browser-only access checks in front of an IdP by combining:

1. mTLS verification signal from edge proxy/LB.
2. Signed `X-Sentinel-Attestation` header (Ed25519 JWS).
3. Conditional access guards (source CIDR + User-Agent prefix).
4. Replay protection (nonce cache + timestamp freshness).

## Threat-model notes

- **Threat**: Chrome or unmanaged browser attempts direct IdP login.
  - **Mitigation**: deny when mTLS and signed attestation are absent.
- **Threat**: Replay of previously captured attestation header.
  - **Mitigation**: nonce cache + 60-second freshness window.
- **Threat**: Stolen browser token from low-posture endpoint.
  - **Mitigation**: posture threshold check before forward.

## Observability hooks

- Per-decision JSON response reason codes for allow/deny.
- Freshness/replay/UA/IP reject reasons available for log aggregation.
- `GET /healthz` endpoint for basic liveness.

## Run locally

```bash
cd services/attestation-gateway
SENTINEL_KEYS='device-123:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
go run ./cmd/gateway
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8090` | HTTP listen address |
| `SENTINEL_KEYS` | required | device-to-public-key map (`device_id:base64pubkey,...`) |
| `SENTINEL_MIN_POSTURE` | `80` | minimum posture score |
| `SENTINEL_FRESHNESS_SECONDS` | `60` | max age of attestation timestamp |
| `SENTINEL_ALLOWED_UA_PREFIX` | `NNSECSentinel/` | allowed browser user-agent prefix |
| `SENTINEL_ALLOWED_CIDRS` | localhost + RFC1918 | allowlisted source networks |

## Tests

```bash
cd services/attestation-gateway
go test ./...
```
