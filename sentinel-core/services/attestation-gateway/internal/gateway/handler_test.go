// Copyright (c) 2026 NNSEC Sentinel
// SPDX-License-Identifier: AGPL-3.0-only
package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthorizeValidRequest(t *testing.T) {
	deviceID := "device-123"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg := mustTestConfig(t, map[string]ed25519.PublicKey{deviceID: pub})
	authz := NewAuthorizer(cfg)
	authz.now = func() time.Time { return time.Unix(1737900050, 0) }

	claims := AttestationClaims{
		DeviceID:       deviceID,
		UserHint:       "firudin@bamboo-card.com",
		PostureScore:   95,
		Timestamp:      1737900050,
		Nonce:          "abc-123",
		BrowserVersion: "1.4.2",
		OSVersion:      "macOS 14.6",
	}
	token := signToken(t, deviceID, claims, priv)

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.RemoteAddr = "127.0.0.1:44444"
	req.Header.Set("X-Sentinel-mTLS-Verified", "true")
	req.Header.Set("X-Sentinel-Attestation", token)
	req.Header.Set("X-Forwarded-Client-Cert", "Subject=\"CN=device-123,O=Bamboo Card\"")
	req.Header.Set("User-Agent", "NNSECSentinel/1.4.2")

	rr := httptest.NewRecorder()
	authz.Authorize(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestAuthorizeReplayBlocked(t *testing.T) {
	deviceID := "device-123"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	cfg := mustTestConfig(t, map[string]ed25519.PublicKey{deviceID: pub})
	authz := NewAuthorizer(cfg)
	authz.now = func() time.Time { return time.Unix(1737900050, 0) }

	claims := AttestationClaims{
		DeviceID:       deviceID,
		UserHint:       "user@bamboo-card.com",
		PostureScore:   90,
		Timestamp:      1737900050,
		Nonce:          "same-nonce",
		BrowserVersion: "1.4.2",
		OSVersion:      "Windows 11",
	}
	token := signToken(t, deviceID, claims, priv)

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.RemoteAddr = "127.0.0.1:11111"
	req.Header.Set("X-Sentinel-mTLS-Verified", "true")
	req.Header.Set("X-Sentinel-Attestation", token)
	req.Header.Set("X-Forwarded-Client-Cert", "Subject=\"CN=device-123,O=Bamboo Card\"")
	req.Header.Set("User-Agent", "NNSECSentinel/1.4.2")

	rr1 := httptest.NewRecorder()
	authz.Authorize(rr1, req)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", rr1.Code)
	}

	rr2 := httptest.NewRecorder()
	authz.Authorize(rr2, req)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected replay to fail, got %d", rr2.Code)
	}
}

func TestAuthorizePostureThresholdBlocked(t *testing.T) {
	deviceID := "device-123"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	cfg := mustTestConfig(t, map[string]ed25519.PublicKey{deviceID: pub})
	authz := NewAuthorizer(cfg)
	authz.now = func() time.Time { return time.Unix(1737900050, 0) }

	claims := AttestationClaims{
		DeviceID:       deviceID,
		UserHint:       "user@bamboo-card.com",
		PostureScore:   50,
		Timestamp:      1737900050,
		Nonce:          "nonce-low-posture",
		BrowserVersion: "1.4.2",
		OSVersion:      "Ubuntu 24.04",
	}
	token := signToken(t, deviceID, claims, priv)

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.RemoteAddr = "127.0.0.1:11111"
	req.Header.Set("X-Sentinel-mTLS-Verified", "true")
	req.Header.Set("X-Sentinel-Attestation", token)
	req.Header.Set("X-Forwarded-Client-Cert", "Subject=\"CN=device-123,O=Bamboo Card\"")
	req.Header.Set("User-Agent", "NNSECSentinel/1.4.2")

	rr := httptest.NewRecorder()
	authz.Authorize(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected low posture to fail, got %d", rr.Code)
	}
}

func TestAuthorizeUserAgentBlocked(t *testing.T) {
	deviceID := "device-123"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	cfg := mustTestConfig(t, map[string]ed25519.PublicKey{deviceID: pub})
	authz := NewAuthorizer(cfg)
	authz.now = func() time.Time { return time.Unix(1737900050, 0) }

	claims := AttestationClaims{
		DeviceID:       deviceID,
		UserHint:       "user@bamboo-card.com",
		PostureScore:   95,
		Timestamp:      1737900050,
		Nonce:          "nonce-ua",
		BrowserVersion: "1.4.2",
		OSVersion:      "macOS 14.6",
	}
	token := signToken(t, deviceID, claims, priv)

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.RemoteAddr = "127.0.0.1:11111"
	req.Header.Set("X-Sentinel-mTLS-Verified", "true")
	req.Header.Set("X-Sentinel-Attestation", token)
	req.Header.Set("X-Forwarded-Client-Cert", "Subject=\"CN=device-123,O=Bamboo Card\"")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/123")

	rr := httptest.NewRecorder()
	authz.Authorize(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected invalid UA to fail, got %d", rr.Code)
	}
}

func mustTestConfig(t *testing.T, keys map[string]ed25519.PublicKey) Config {
	t.Helper()
	_, cidr, err := net.ParseCIDR("127.0.0.1/32")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return Config{
		MinPostureScore: 80,
		FreshnessWindow: 60 * time.Second,
		AllowedUAPrefix: "NNSECSentinel/",
		AllowedCIDRs:    []*net.IPNet{cidr},
		DeviceKeys:      keys,
	}
}

func signToken(t *testing.T, keyID string, claims AttestationClaims, priv ed25519.PrivateKey) string {
	t.Helper()
	header := map[string]string{
		"alg": "EdDSA",
		"kid": keyID,
		"typ": "JWT",
	}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadRaw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerRaw)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadRaw)
	signedPart := headerB64 + "." + payloadB64
	signature := ed25519.Sign(priv, []byte(signedPart))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)
	return signedPart + "." + sigB64
}
