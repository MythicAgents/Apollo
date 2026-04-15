# NL to Policy Compiler PoC

## Purpose
Converts plain-English policy requests into Sentinel Rego policy fragments using Claude with deterministic post-validation.

## Threat Model Notes
- Prompt injection attempts are constrained by strict instruction templates and output schema validation.
- API keys are consumed from environment variables and never logged.
- Generated policies are checked against deny-list patterns before acceptance.

## Run
```bash
npm install
ANTHROPIC_API_KEY=... npm run compile -- "contractors cannot download from github.com"
```

## Test
```bash
npm run test
```

## Observability
- Structured logs include trace IDs and prompt hash, not full prompts.
- Metrics: compile latency p95 target < 1500 ms, rejection rate, invalid syntax rate.

