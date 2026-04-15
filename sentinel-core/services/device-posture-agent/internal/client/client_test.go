// Copyright (c) NNSEC Sentinel.
// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendReportSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST got %s", r.Method)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	report := Report{
		DeviceID:    "dev-test",
		CollectedAt: time.Now().UTC(),
		OSVersion:   "linux",
	}
	if err := SendReport(context.Background(), server.URL, report); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

