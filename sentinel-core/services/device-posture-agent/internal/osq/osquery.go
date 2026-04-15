// Copyright (c) NNSEC Sentinel.
// SPDX-License-Identifier: AGPL-3.0-only

package osq

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/nnsec-sentinel/project-sentinel/services/device-posture-agent/internal/client"
)

var queryFn = Query

// Query runs osqueryi SQL and returns a list of rows.
func Query(sql string) ([]map[string]string, error) {
	cmd := exec.Command("osqueryi", "--json", sql)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("osquery failed: %w", err)
	}

	var rows []map[string]string
	if err := json.Unmarshal(output, &rows); err != nil {
		return nil, fmt.Errorf("failed to parse osquery json: %w", err)
	}
	return rows, nil
}

// CollectPosture pulls a minimal posture snapshot from osquery and local runtime data.
func CollectPosture(_ context.Context) (client.Report, error) {
	results, err := queryFn("select version from os_version;")
	if err != nil {
		return client.Report{}, err
	}

	report := client.Report{
		DeviceID:     fmt.Sprintf("dev-%d", time.Now().UnixNano()),
		CollectedAt:  time.Now().UTC(),
		OSVersion:    runtime.GOOS,
		QueryResults: map[string]interface{}{"os_version": results},
	}
	return report, nil
}
