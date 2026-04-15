/*
 * Copyright (C) 2026 NNSEC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import type { ReactNode } from "react";

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "Inter, Arial, sans-serif", background: "#0b1020", color: "#f7f8fb" }}>
        {children}
      </body>
    </html>
  );
}
