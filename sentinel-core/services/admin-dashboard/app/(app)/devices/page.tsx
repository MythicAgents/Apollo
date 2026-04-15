"use client";

// Copyright (c) 2026 NNSEC Sentinel
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo } from "react";

const devices = [
  { id: "dev-001", user: "amir@bamboo-card.com", posture: "healthy", os: "macOS 14.6" },
  { id: "dev-002", user: "qa@bamboo-card.com", posture: "warning", os: "Windows 11" },
  { id: "dev-003", user: "ops@nnsec.io", posture: "healthy", os: "Ubuntu 24.04" }
];

export default function DevicesPage() {
  const unhealthyCount = useMemo(
    () => devices.filter((d) => d.posture !== "healthy").length,
    []
  );

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-4">
      <h1 className="text-2xl font-semibold">Device Fleet</h1>
      <p className="text-slate-600">
        Posture warnings: <span className="font-semibold">{unhealthyCount}</span>
      </p>
      <div className="rounded border divide-y">
        {devices.map((device) => (
          <div className="flex items-center justify-between p-4" key={device.id}>
            <div>
              <p className="font-medium">{device.id}</p>
              <p className="text-sm text-slate-500">{device.user}</p>
            </div>
            <div className="text-right">
              <p className="text-sm">{device.os}</p>
              <p className="text-sm uppercase">{device.posture}</p>
            </div>
          </div>
        ))}
      </div>
    </main>
  );
}
