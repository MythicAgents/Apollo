// Copyright (c) 2026 NNSEC Sentinel
// SPDX-License-Identifier: AGPL-3.0-only
package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime controls for browser-only IdP enforcement.
type Config struct {
	MinPostureScore int
	FreshnessWindow time.Duration
	AllowedUAPrefix string
	AllowedCIDRs    []*net.IPNet
	DeviceKeys      map[string]ed25519.PublicKey
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		MinPostureScore: 80,
		FreshnessWindow: 60 * time.Second,
		AllowedUAPrefix: "NNSECSentinel/",
	}

	if raw := os.Getenv("SENTINEL_MIN_POSTURE"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse SENTINEL_MIN_POSTURE: %w", err)
		}
		cfg.MinPostureScore = v
	}

	if raw := os.Getenv("SENTINEL_FRESHNESS_SECONDS"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse SENTINEL_FRESHNESS_SECONDS: %w", err)
		}
		cfg.FreshnessWindow = time.Duration(v) * time.Second
	}

	if raw := os.Getenv("SENTINEL_ALLOWED_UA_PREFIX"); raw != "" {
		cfg.AllowedUAPrefix = raw
	}

	cidrCSV := os.Getenv("SENTINEL_ALLOWED_CIDRS")
	if cidrCSV == "" {
		cidrCSV = "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	}
	cidrs, err := parseCIDRs(cidrCSV)
	if err != nil {
		return Config{}, err
	}
	cfg.AllowedCIDRs = cidrs

	keyMap, err := parseDeviceKeys(os.Getenv("SENTINEL_KEYS"))
	if err != nil {
		return Config{}, err
	}
	cfg.DeviceKeys = keyMap

	return cfg, nil
}

func parseCIDRs(raw string) ([]*net.IPNet, error) {
	parts := strings.Split(raw, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		c := strings.TrimSpace(part)
		if c == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr %q: %w", c, err)
		}
		out = append(out, ipnet)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no allowed CIDRs configured")
	}
	return out, nil
}

// SENTINEL_KEYS format:
// device-1:base64-ed25519-pubkey,device-2:base64-ed25519-pubkey
func parseDeviceKeys(raw string) (map[string]ed25519.PublicKey, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("SENTINEL_KEYS cannot be empty")
	}

	out := map[string]ed25519.PublicKey{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid key mapping %q", pair)
		}
		deviceID := strings.TrimSpace(kv[0])
		keyB64 := strings.TrimSpace(kv[1])
		pubRaw, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey for %q: %w", deviceID, err)
		}
		if len(pubRaw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pubkey size for %q must be %d", deviceID, ed25519.PublicKeySize)
		}
		out[deviceID] = ed25519.PublicKey(pubRaw)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid keys parsed from SENTINEL_KEYS")
	}
	return out, nil
}
