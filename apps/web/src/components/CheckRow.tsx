import type { CheckRow as CheckRowData } from "@/lib/verify-flow";
import { TrustSignalBadge } from "./TrustSignalBadge";

/** One §9.2 check rendered as it resolves: the trust signal, the computed values
 *  it saw ("the math"), and any honesty caveat about the depth of the check. */
export function CheckRow({ row, revealed }: { row: CheckRowData; revealed: boolean }) {
  return (
    <li
      className="rounded-lg border border-border p-4 transition-all duration-300"
      style={{
        opacity: revealed ? 1 : 0,
        transform: revealed ? "translateY(0)" : "translateY(4px)",
      }}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-baseline gap-2.5">
          <span className="font-mono text-xs text-muted">#{row.num}</span>
          <span className="font-medium">{row.name}</span>
        </div>
        <TrustSignalBadge signal={row.signal} />
      </div>

      {row.signal.detail && (
        <p className="mt-2 text-sm text-muted">{row.signal.detail}</p>
      )}

      {row.math.length > 0 && (
        <dl className="mt-3 grid gap-1.5 sm:grid-cols-[max-content_1fr] sm:gap-x-4">
          {row.math.map((m, i) => (
            <div key={i} className="contents">
              <dt className="text-xs text-muted">{m.label}</dt>
              <dd
                className={`text-xs ${m.mono ? "font-mono break-all" : ""}`}
                title={m.full ?? undefined}
              >
                {m.value}
              </dd>
            </div>
          ))}
        </dl>
      )}

      {row.depthNote && (
        <p className="mt-3 border-t border-border pt-2 text-xs text-muted">
          {row.depthNote}
        </p>
      )}
    </li>
  );
}
