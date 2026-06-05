import { TIER_META, toResolvedSignal } from "@/lib/trust-signal";
import type { Verdict } from "@/lib/verify-flow";
import { TrustSignalBadge } from "./TrustSignalBadge";

/** The rolled-up headline verdict (P5 glance layer). Disclosure, not validation
 *  (P1): the detail line names what was checked, not whether the content is true. */
export function VerdictBanner({ verdict }: { verdict: Verdict }) {
  const meta = TIER_META[verdict.tier];
  const signal = toResolvedSignal({ tier: verdict.tier, label: verdict.headline });
  return (
    <div
      className="rounded-xl border p-5"
      style={{
        borderColor: meta.colorVar,
        // a faint tint of the tier color
        background: `color-mix(in srgb, ${meta.colorVar} 6%, transparent)`,
      }}
    >
      <div className="flex items-center gap-2.5" style={{ color: meta.colorVar }}>
        <TrustSignalBadge signal={signal} showLabel={false} />
        <h2 className="font-display text-xl font-semibold">{verdict.headline}</h2>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-foreground">{verdict.detail}</p>
    </div>
  );
}
