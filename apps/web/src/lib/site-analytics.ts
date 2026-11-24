import { resolveAnalytics } from "./analytics.ts";

/**
 * This build's analytics, decided once: the root layout renders the tag from
 * it and `/privacy` renders its analytics paragraph from it, so the two cannot
 * disagree (typedstandards#85). Each variable is read by its literal name, and
 * `next.config.ts` lists all three under `env`, so `next build` replaces each
 * with its value here: every page, dynamic or prerendered, renders from the
 * build's values. The rule is `resolveAnalytics`'s.
 */
export const SITE_ANALYTICS = resolveAnalytics({
  NEXT_PUBLIC_ANALYTICS_SERVICE: process.env.NEXT_PUBLIC_ANALYTICS_SERVICE,
  NEXT_PUBLIC_ANALYTICS_ID: process.env.NEXT_PUBLIC_ANALYTICS_ID,
  NEXT_PUBLIC_ANALYTICS_DASHBOARD_URL: process.env.NEXT_PUBLIC_ANALYTICS_DASHBOARD_URL,
});
