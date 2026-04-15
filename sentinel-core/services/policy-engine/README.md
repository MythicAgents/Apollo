# Sentinel Policy Engine PoC (FastAPI + OPA)

## Purpose
Evaluate browser and network policy decisions using Rego with a thin FastAPI adapter.

## Run
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

## Test
```bash
python3 -m unittest discover -s tests -p "test_*.py" -q
```

## API
- `GET /healthz`
- `POST /v1/decision`

## Security Notes
- No production auth in this PoC
- OPA sidecar should run with mTLS in production

## Threat Model Note
Primary threats: policy bypass, forged identity claims, replayed inputs, stale policy bundle, denial-of-service.

## Observability
- JSON structured logs on decision requests
- p95 decision latency should remain under 10 ms at OPA layer, <50 ms API end-to-end
