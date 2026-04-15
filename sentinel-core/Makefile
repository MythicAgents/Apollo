SHELL := /bin/bash

.PHONY: up down logs test-policy test-go test-dashboard test-telemetry test-session-recorder test-password-vault test-nl-compiler test-vpn test-attestation-gateway test-all lint-readme

up:
	docker compose up -d

down:
	docker compose down -v

logs:
	docker compose logs -f --tail=200

test-policy:
	cd services/policy-engine && python3 -m unittest tests/test_policy.py -q

test-go:
	cd services/device-posture-agent && go test ./...

test-dashboard:
	cd services/admin-dashboard && node --test tests/routes.test.mjs

test-telemetry:
	cd services/telemetry-ingestion && python3 -m unittest discover -s tests -p "test_*.py"

test-session-recorder:
	cd services/session-recorder && node --test tests/recorder.test.js

test-password-vault:
	cd services/password-vault-poc && node --test tests/vault.test.js

test-nl-compiler:
	cd services/nl-policy-compiler && node --test tests/compiler.test.js

test-vpn:
	cd services/vpn-ztna-gateway && node --test tests/config.test.mjs

test-attestation-gateway:
	cd services/attestation-gateway && go test ./...

test-all: test-policy test-go test-dashboard test-telemetry test-session-recorder test-password-vault test-nl-compiler test-vpn test-attestation-gateway

lint-readme:
	@echo "README lint placeholder - integrate markdownlint in CI"
