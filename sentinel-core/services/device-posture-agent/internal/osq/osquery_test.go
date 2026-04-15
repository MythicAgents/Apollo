// Copyright (c) NNSEC Sentinel.
// SPDX-License-Identifier: AGPL-3.0-only
package osq

import (
	"context"
	"testing"
)

func TestCollectPostureWithStubQuery(t *testing.T) {
	original := queryFn
	queryFn = func(_ string) ([]map[string]string, error) {
		return []map[string]string{{"version": "1.0"}}, nil
	}
	t.Cleanup(func() { queryFn = original })

	report, err := CollectPosture(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.DeviceID == "" {
		t.Fatalf("expected non-empty device id")
	}
}

