import type { Metadata } from "next";
import { PrivacyStatement } from "@/components/PrivacyStatement";
import { SITE_ANALYTICS } from "@/lib/site-analytics";
import { SITE_LOOKUP_COUNT } from "@/lib/site-lookup-count";
import { lookupTotals } from "@/lib/count-lookup";

export const metadata: Metadata = {
  title: "Privacy",
  description:
    "What typedstandards.org does when you read it, and when you verify a record with it.",
};

/** The lookup count's totals are read again at most hourly (typedstandards#143). */
export const revalidate = 3600;

/** `/privacy` (typedstandards#85). Its analytics section reads the same
 *  `SITE_ANALYTICS` the root layout renders the tag from; its lookup-count
 *  words render only when this build counts (`SITE_LOOKUP_COUNT`, #143). */
export default async function PrivacyPage() {
  const lookupCount = SITE_LOOKUP_COUNT ? { totals: await lookupTotals() } : null;
  return <PrivacyStatement analytics={SITE_ANALYTICS} lookupCount={lookupCount} />;
}
