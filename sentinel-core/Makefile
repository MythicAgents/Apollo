SHELL := /bin/bash

.PHONY: up down logs test-policy test-go lint-readme

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

lint-readme:
	@echo "README lint placeholder - integrate markdownlint in CI"
