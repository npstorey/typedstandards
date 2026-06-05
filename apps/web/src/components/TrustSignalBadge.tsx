import { TIER_META, type ResolvedTrustSignal, type TrustIconName } from "@/lib/trust-signal";

function Glyph({ name }: { name: TrustIconName }) {
  const common = {
    width: 16,
    height: 16,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.6,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };
  switch (name) {
    case "check":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.5" />
          <path d="M5.2 8.2l2 2 3.6-4" />
        </svg>
      );
    case "warning":
      return (
        <svg {...common}>
          <path d="M8 2.2l6 11H2z" />
          <path d="M8 6.6v3.1" />
          <circle cx="8" cy="11.4" r="0.2" />
        </svg>
      );
    case "error":
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.5" />
          <path d="M5.6 5.6l4.8 4.8M10.4 5.6l-4.8 4.8" />
        </svg>
      );
    case "info":
    default:
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.5" />
          <path d="M8 7.3v3.4" />
          <circle cx="8" cy="5.2" r="0.2" />
        </svg>
      );
  }
}

/** A trust-tier glyph + label, colored by the tier token. The full `status →
 *  { tier, icon, copy }` vocabulary lives in trust-signal.ts. */
export function TrustSignalBadge({
  signal,
  showLabel = true,
}: {
  signal: ResolvedTrustSignal;
  showLabel?: boolean;
}) {
  const meta = TIER_META[signal.tier];
  return (
    <span
      className="inline-flex items-center gap-1.5"
      style={{ color: meta.colorVar }}
      role="img"
      aria-label={`${meta.ariaLabel}: ${signal.label}`}
    >
      <Glyph name={signal.icon} />
      {showLabel && <span className="text-sm font-medium">{signal.label}</span>}
    </span>
  );
}
