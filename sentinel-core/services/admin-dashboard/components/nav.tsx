"use client";

// Copyright (c) 2026 NNSEC Sentinel
// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/", label: "Overview" },
  { href: "/tenants", label: "Tenants" },
  { href: "/devices", label: "Devices" },
  { href: "/login", label: "Login" },
];

export function Nav() {
  const pathname = usePathname();

  return (
    <nav style={{ display: "flex", gap: "1rem", marginBottom: "1.5rem" }}>
      {links.map((link) => (
        <Link
          key={link.href}
          href={link.href}
          style={{
            textDecoration: pathname === link.href ? "underline" : "none",
          }}
        >
          {link.label}
        </Link>
      ))}
    </nav>
  );
}
