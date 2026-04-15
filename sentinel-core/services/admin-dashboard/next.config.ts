/**
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  experimental: {
    typedRoutes: true
  }
};

export default nextConfig;
