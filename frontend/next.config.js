/** @type {import('next').NextConfig} */
const backendBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000";
const allowUnsafeEval = process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : "";
const cspDirectives = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${allowUnsafeEval}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' blob: data:",
  `connect-src 'self' ${backendBaseUrl} ws://127.0.0.1:3000 wss://127.0.0.1:3000`,
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "report-to csp-endpoint",
  `report-uri ${backendBaseUrl}/__csp_report`,
];

const nextConfig = {
  reactStrictMode: true,
  i18n: {
    locales: ["en", "pt"],
    defaultLocale: "en",
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "geolocation=(), microphone=(), camera=()" },
          {
            key: "Content-Security-Policy-Report-Only",
            value: cspDirectives.join("; "),
          },
          {
            key: "Reporting-Endpoints",
            value: `csp-endpoint="${backendBaseUrl}/__csp_report"`,
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
