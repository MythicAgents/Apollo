# Sentinel Device Posture Agent (Go)

Collects host posture attributes via osquery and sends signed reports to the backend.

## Threat model note
- Spoofed posture payloads: mitigate by mTLS and signed payload checks.
- Agent binary tampering: signed binaries + integrity checks.

## Build and run
```bash
go run ./cmd/agent
```

## Observability
- JSON logs to stdout
- report counters should be exported in future via OTEL metrics

## Tests
```bash
go test ./...
```
