# Session Recorder Library (rrweb + encrypted upload)

## Purpose
Captures browser sessions with rrweb and uploads encrypted chunks to MinIO-compatible object storage.

## Threat model note
- Protect recording confidentiality: AES-GCM before network transfer.
- Prevent replay tampering: include chunk sequence + auth tag per chunk.
- Do not record sensitive fields; allow caller to configure masking selectors.

## Observability hooks
- `onEvent` callback receives record-start/record-stop/upload outcomes.

## Tests
```bash
npm test
```

## Quick start
```bash
npm install
```

```ts
import { startRecorder } from "./src";

const stop = startRecorder({
  tenantId: "tenant-bamboo",
  sessionId: "session-123",
  passphrase: "replace-me-in-production",
  uploader: async (payload) => {
    await fetch("http://localhost:9000/recordings/session-123", {
      method: "PUT",
      body: payload
    });
  }
});

setTimeout(() => stop(), 60000);
```
