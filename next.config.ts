import type { NextConfig } from "next";

// SECURITY HEADERS (QA audit 2026-10-23): baseline hardening on EVERY
// response — previously the app shipped no X-Content-Type-Options / CSP /
// X-Frame-Options / Referrer-Policy at all (only report downloads carried
// nosniff). The report viewer renders engine HTML inside sandbox=""
// iframes (srcDoc), which is unaffected by these headers; the CSP below
// keeps Next.js hydration (inline bootstrap scripts) functional.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
