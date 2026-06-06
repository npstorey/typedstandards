import type { HostRecognition } from "@/lib/verify-flow";
import { VerdictCard } from "./VerdictBanner";

/** The host-recognition verdict (Phase D / Q47) — the SECOND, independent
 *  dimension, rendered as its own clearly-labelled card beside the cryptographic
 *  verdict. Recognition discloses who published a package (per the curated host
 *  directory); it never validates the content, and it neither upgrades a failed
 *  cryptographic verdict nor downgrades a valid one. Only a confirmed "known
 *  publisher" gets a profile link — a recognized-but-unconfirmed host does not,
 *  so the click-through never implies a recognition the registry itself withholds. */
export function RecognitionBanner({ recognition }: { recognition: HostRecognition }) {
  const { signal, status, publisher } = recognition;
  const headlineHref =
    status === "known_publisher" && publisher?.profileUrl ? publisher.profileUrl : undefined;
  return (
    <VerdictCard
      tier={signal.tier}
      eyebrow="Publisher recognition"
      headline={signal.label}
      detail={signal.detail}
      headlineHref={headlineHref}
    />
  );
}
