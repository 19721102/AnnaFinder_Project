/** @type {import('next').NextConfig} */
const backendBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000";
const cspDirectives = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
  `connect-src 'self' ${backendBaseUrl} ws://127.0.0.1:3000 wss://127.0.0.1:3000`,
  "report-to csp-endpoint",
  "report-uri /api/v1/csp-report",
];
const reportingEndpointsValue = 'csp-endpoint="/api/v1/csp-report"';
const reportToValue = JSON.stringify({
  group: "csp-endpoint",
  max_age: 10886400,
  endpoints: [{ url: "/api/v1/csp-report" }],
});

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "Permissions-Policy", value: "geolocation=(), microphone=(), camera=()" },
];

const cspHeaders = [
  {
    key: "Content-Security-Policy-Report-Only",
    value: cspDirectives.join("; "),
  },
  {
    key: "Reporting-Endpoints",
    value: reportingEndpointsValue,
  },
  {
    key: "Report-To",
    value: reportToValue,
  },
];

const nextConfig = {
  reactStrictMode: true,
  i18n: {
    locales: ["en", "pt"],
    defaultLocale: "en",
  },
  async headers() {
    const headers = [...securityHeaders, ...cspHeaders];
    if (process.env.NODE_ENV === "production") {
      headers.push({
        key: "Strict-Transport-Security",
        value: "max-age=31536000; includeSubDomains",
      });
    }
    return [
      {
        source: "/(.*)",
        headers,
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: `${backendBaseUrl}/api/v1/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
