// Copyright (c) 2026 NNSEC Sentinel
// SPDX-License-Identifier: AGPL-3.0-only
package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type attestationHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// AttestationClaims are sent by Sentinel in X-Sentinel-Attestation.
type AttestationClaims struct {
	DeviceID       string `json:"device_id"`
	UserHint       string `json:"user_hint"`
	PostureScore   int    `json:"posture_score"`
	Timestamp      int64  `json:"timestamp"`
	Nonce          string `json:"nonce"`
	BrowserVersion string `json:"browser_version"`
	OSVersion      string `json:"os_version"`
}

// Authorizer enforces layered browser attestation checks before IdP access.
type Authorizer struct {
	cfg    Config
	now    func() time.Time
	mu     sync.Mutex
	nonces map[string]time.Time
}

func NewAuthorizer(cfg Config) *Authorizer {
	return &Authorizer{
		cfg:    cfg,
		now:    time.Now,
		nonces: map[string]time.Time{},
	}
}

func (a *Authorizer) Healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
	})
}

func (a *Authorizer) Authorize(w http.ResponseWriter, r *http.Request) {
	// Mechanism 1: mTLS proof forwarded by edge proxy/load balancer.
	if !isMTLSVerified(r) {
		deny(w, "mtls_not_verified")
		return
	}

	// Mechanism 4 (starter policy): user-agent and IP constraints.
	if !strings.HasPrefix(r.UserAgent(), a.cfg.AllowedUAPrefix) {
		deny(w, "user_agent_not_allowed")
		return
	}
	if !a.clientIPAllowed(clientIP(r)) {
		deny(w, "source_ip_not_allowed")
		return
	}

	// Mechanism 2: signed short-lived attestation header.
	token := strings.TrimSpace(r.Header.Get("X-Sentinel-Attestation"))
	if token == "" {
		deny(w, "missing_attestation_header")
		return
	}
	claims, err := a.verifyAttestationToken(token)
	if err != nil {
		deny(w, fmt.Sprintf("invalid_attestation:%v", err))
		return
	}

	if claims.PostureScore < a.cfg.MinPostureScore {
		deny(w, "posture_below_threshold")
		return
	}
	if !a.isFresh(claims.Timestamp) {
		deny(w, "stale_attestation")
		return
	}
	if a.isReplay(claims.Nonce, claims.Timestamp) {
		deny(w, "replay_nonce")
		return
	}

	// Bind cert subject to attested device when XFCC is available.
	xfcc := r.Header.Get("X-Forwarded-Client-Cert")
	if xfcc != "" && !strings.Contains(strings.ToLower(xfcc), strings.ToLower(claims.DeviceID)) {
		deny(w, "cert_subject_device_mismatch")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"allow":           true,
		"device_id":       claims.DeviceID,
		"user_hint":       claims.UserHint,
		"posture_score":   claims.PostureScore,
		"browser_version": claims.BrowserVersion,
		"reason":          "all_checks_passed",
	})
}

func (a *Authorizer) verifyAttestationToken(token string) (AttestationClaims, error) {
	var claims AttestationClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, fmt.Errorf("token_parts")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, fmt.Errorf("header_b64")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, fmt.Errorf("payload_b64")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims, fmt.Errorf("signature_b64")
	}

	var hdr attestationHeader
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return claims, fmt.Errorf("header_json")
	}
	if strings.ToUpper(hdr.Algorithm) != "EDDSA" {
		return claims, fmt.Errorf("alg_not_eddsa")
	}
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return claims, fmt.Errorf("claims_json")
	}
	if claims.DeviceID == "" || claims.Nonce == "" || claims.Timestamp == 0 {
		return claims, fmt.Errorf("claims_missing_required_fields")
	}

	keyID := hdr.KeyID
	if keyID == "" {
		keyID = claims.DeviceID
	}
	pub, ok := a.cfg.DeviceKeys[keyID]
	if !ok {
		return claims, fmt.Errorf("unknown_device_key")
	}

	message := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(pub, message, sig) {
		return claims, fmt.Errorf("signature_invalid")
	}
	return claims, nil
}

func (a *Authorizer) isFresh(ts int64) bool {
	now := a.now().Unix()
	delta := now - ts
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= a.cfg.FreshnessWindow
}

func (a *Authorizer) isReplay(nonce string, ts int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	expiration := now.Add(-a.cfg.FreshnessWindow)
	for k, seen := range a.nonces {
		if seen.Before(expiration) {
			delete(a.nonces, k)
		}
	}
	if _, exists := a.nonces[nonce]; exists {
		return true
	}
	issuedAt := time.Unix(ts, 0)
	if issuedAt.Before(expiration) {
		return true
	}
	a.nonces[nonce] = now
	return false
}

func (a *Authorizer) clientIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range a.cfg.AllowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isMTLSVerified(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("X-Sentinel-mTLS-Verified"), "true") {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-SSL-Client-Verify"), "SUCCESS") {
		return true
	}
	return false
}

func clientIP(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if parsed := net.ParseIP(first); parsed != nil {
			return parsed
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(r.RemoteAddr)
}

func deny(w http.ResponseWriter, reason string) {
	writeJSON(w, http.StatusForbidden, map[string]any{
		"allow":  false,
		"reason": reason,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
