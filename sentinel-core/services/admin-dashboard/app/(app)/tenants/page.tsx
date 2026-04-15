"use client";

// Copyright (c) 2026 NNSEC Sentinel
// SPDX-License-Identifier: AGPL-3.0-only

export default function TenantsPage() {
  const tenants = [
    { id: "ten_bamboo", name: "Bamboo Card", plan: "enterprise", seats: 420 },
    { id: "ten_nnsec-mssp", name: "NNSEC MSP", plan: "mssp", seats: 1200 },
  ];

  return (
    <main style={{ padding: 24 }}>
      <h1>Tenants</h1>
      <p>Multi-tenant inventory (PoC data).</p>
      <table style={{ borderCollapse: "collapse", width: "100%", marginTop: 16 }}>
        <thead>
          <tr>
            <th style={{ borderBottom: "1px solid #ccc", textAlign: "left" }}>Tenant ID</th>
            <th style={{ borderBottom: "1px solid #ccc", textAlign: "left" }}>Name</th>
            <th style={{ borderBottom: "1px solid #ccc", textAlign: "left" }}>Plan</th>
            <th style={{ borderBottom: "1px solid #ccc", textAlign: "left" }}>Seats</th>
          </tr>
        </thead>
        <tbody>
          {tenants.map((tenant) => (
            <tr key={tenant.id}>
              <td style={{ padding: "8px 0" }}>{tenant.id}</td>
              <td>{tenant.name}</td>
              <td>{tenant.plan}</td>
              <td>{tenant.seats}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
