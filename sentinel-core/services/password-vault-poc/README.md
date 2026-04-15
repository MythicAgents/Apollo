# Sentinel Password Vault PoC

## Scope
`password-vault-poc` demonstrates client-side E2EE key derivation and encryption primitives.

## Local use
```bash
npm install
npm run test
```

## License
- SPDX-License-Identifier: AGPL-3.0-only

## License
SPDX-License-Identifier: AGPL-3.0-only

## Threat-model notes
- Protects at-rest vault data by deriving encryption keys from user secret material (PBKDF2 in PoC; Argon2id for production).
- Does not include authenticated SRP/OPAQUE login flow in this scaffold.

## Observability
- Vault operations emit structured event names to be integrated with OpenTelemetry spans in production.
