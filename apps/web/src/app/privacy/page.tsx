import type { Metadata } from "next";
import { PrivacyStatement } from "@/components/PrivacyStatement";
import { SITE_ANALYTICS } from "@/lib/site-analytics";

export const metadata: Metadata = {
  title: "Privacy",
  description:
    "What typedstandards.org does when you read it, and when you verify a record with it.",
};

/** `/privacy` (typedstandards#85). Its analytics section reads the same
 *  `SITE_ANALYTICS` the root layout renders the tag from. */
export default function PrivacyPage() {
  return <PrivacyStatement analytics={SITE_ANALYTICS} />;
}
