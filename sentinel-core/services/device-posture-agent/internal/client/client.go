// Copyright (c) NNSEC Sentinel.
// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Report struct {
	DeviceID     string                 `json:"device_id"`
	CollectedAt  time.Time              `json:"collected_at"`
	OSVersion    string                 `json:"os_version"`
	QueryResults map[string]interface{} `json:"query_results"`
}

func Send(ctx context.Context, url string, r Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// SendReport is an explicit wrapper used by callers for readability.
func SendReport(ctx context.Context, url string, r Report) error {
	return Send(ctx, url, r)
}
