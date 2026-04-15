# Sentinel Admin Dashboard Skeleton

This module provides a minimal Next.js 15 + TypeScript admin console starter.

## Scope

- Login route (`/login`)
- Tenants route (`/tenants`)
- Devices route (`/devices`)
- Basic navigation and role-aware shell placeholder

## Run

```bash
npm install
npm run dev
npm test
```

## Security notes

- Production auth must be Keycloak OIDC with PKCE
- Route authorization must be middleware-enforced, not UI-only
- CSP must be strict, with nonce-based script policy

## Observability hooks

- Add OpenTelemetry web SDK in `app/layout.tsx`
- Emit route transition traces and API timings

## Threat model note

Main threats: token theft in browser storage, CSRF on admin mutations, privilege escalation via missing backend RBAC.

