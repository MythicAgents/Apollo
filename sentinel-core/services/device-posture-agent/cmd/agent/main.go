// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"log"
	"time"

	"github.com/nnsec-sentinel/project-sentinel/services/device-posture-agent/internal/client"
	"github.com/nnsec-sentinel/project-sentinel/services/device-posture-agent/internal/osq"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report, err := osq.CollectPosture(ctx)
	if err != nil {
		log.Fatalf("collect posture: %v", err)
	}

	if err := client.SendReport(ctx, "http://localhost:8080/posture/report", report); err != nil {
		log.Fatalf("send report: %v", err)
	}

	log.Printf("posture report sent for device=%s", report.DeviceID)
}
