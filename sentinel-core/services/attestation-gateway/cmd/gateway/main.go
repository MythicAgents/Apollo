// Copyright (c) 2026 NNSEC Sentinel
// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/nnsec-sentinel/project-sentinel/services/attestation-gateway/internal/gateway"
)

func main() {
	cfg, err := gateway.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	authz := gateway.NewAuthorizer(cfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", authz.Healthz)
	mux.HandleFunc("/authorize", authz.Authorize)

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8090"
	}

	log.Printf("attestation gateway listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server exit: %v", err)
	}
}
