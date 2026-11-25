import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The analytics variables, fixed at build on every page (typedstandards#85).
  // Next inlines a NEXT_PUBLIC_ name into browser code only: a server component
  // reads it from the environment each time it renders, which on a dynamic
  // route (/verify) is every request. `env` replaces each name with its value
  // at build in server code too, so /verify renders the tag from the same
  // values as the prerendered pages, /privacy among them. Unset is "", which
  // `resolveAnalytics` reads as absent. The dashboard address is the third.
  env: {
    NEXT_PUBLIC_ANALYTICS_SERVICE: process.env.NEXT_PUBLIC_ANALYTICS_SERVICE ?? "",
    NEXT_PUBLIC_ANALYTICS_ID: process.env.NEXT_PUBLIC_ANALYTICS_ID ?? "",
    NEXT_PUBLIC_ANALYTICS_DASHBOARD_URL: process.env.NEXT_PUBLIC_ANALYTICS_DASHBOARD_URL ?? "",
  },
};

export default nextConfig;
