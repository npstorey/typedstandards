import { TIER_META, toResolvedSignal, type TrustTier } from "@/lib/trust-signal";
import type { Verdict } from "@/lib/verify-flow";
import { TrustSignalBadge } from "./TrustSignalBadge";

/** One verdict dimension rendered as a tier-colored card: a small eyebrow naming
 *  the dimension, the tier glyph + headline, and the disclosure detail. Shared by
 *  the two INDEPENDENT dimensions — cryptographic validity and publisher
 *  recognition — so they read as parallel, never as one rolled into the other
 *  (P1: disclosure ≠ validation). */
export function VerdictCard({
  tier,
  eyebrow,
  headline,
  detail,
  headlineHref,
}: {
  tier: TrustTier;
  eyebrow: string;
  headline: string;
  detail?: string;
  /** When set, the headline links here (used for a known publisher's profile —
   *  rendered, never trust-conferring). */
  headlineHref?: string;
}) {
  const meta = TIER_META[tier];
  const signal = toResolvedSignal({ tier, label: headline });
  return (
    <div
      className="rounded-xl border p-5"
      style={{
        borderColor: meta.colorVar,
        // a faint tint of the tier color
        background: `color-mix(in srgb, ${meta.colorVar} 6%, transparent)`,
      }}
    >
      <p className="font-mono text-xs uppercase tracking-[0.15em] text-muted">{eyebrow}</p>
      <div className="mt-1 flex items-center gap-2.5" style={{ color: meta.colorVar }}>
        <TrustSignalBadge signal={signal} showLabel={false} />
        <h2 className="font-display text-xl font-semibold">
          {headlineHref ? (
            <a
              href={headlineHref}
              target="_blank"
              rel="noreferrer"
              className="underline decoration-dotted underline-offset-4 hover:opacity-80"
            >
              {headline}
            </a>
          ) : (
            headline
          )}
        </h2>
      </div>
      {detail && <p className="mt-2 text-sm leading-relaxed text-foreground">{detail}</p>}
    </div>
  );
}

/** The rolled-up cryptographic verdict (P5 glance layer) — one of the two
 *  dimensions. Disclosure, not validation (P1): the detail names what was checked,
 *  not whether the content is true. */
export function VerdictBanner({ verdict }: { verdict: Verdict }) {
  return (
    <VerdictCard
      tier={verdict.tier}
      eyebrow="Cryptographic validity"
      headline={verdict.headline}
      detail={verdict.detail}
    />
  );
}
