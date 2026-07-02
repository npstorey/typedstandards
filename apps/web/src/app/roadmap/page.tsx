import type { Metadata } from "next";

import { SPONSOR_LINE } from "@/lib/site-config";

export const metadata: Metadata = {
  title: "Roadmap",
  description:
    "Where the Typed Standards work stands: what is built, what is designed, and what is upcoming.",
};

type BuildState = "built" | "designed" | "upcoming";

const STATE_STYLE: Record<BuildState, { dot: string; label: string }> = {
  built: { dot: "bg-trust-verified", label: "built" },
  designed: { dot: "bg-accent", label: "designed" },
  upcoming: { dot: "bg-muted", label: "upcoming" },
};

type Milestone = {
  title: string;
  state: BuildState;
  quarter?: string;
  body: string;
};

/**
 * Milestones mirror the canonical civic-ai-tools public roadmap
 * (v2026.Q2.1) — the reference implementation's roadmap is the source of
 * truth; this page is the Typed Standards view of it. Quarter granularity
 * only on this public page.
 */
const MILESTONES: Milestone[] = [
  {
    title: "Signed evidence packages",
    state: "built",
    quarter: "2026 Q2",
    body: "Analyses publish as content-addressable, cryptographically signed evidence packages — Ed25519 signatures over canonical JSON, RFC 3161 timestamps, and a public transparency-log entry for every publish.",
  },
  {
    title: "Shared verification core",
    state: "built",
    quarter: "2026 Q2",
    body: "@typedstandards/verify-core is published to npm and consumed by more than one codebase, so every verifier depends on one versioned source that cannot drift.",
  },
  {
    title: "Independent verifier",
    state: "built",
    quarter: "2026 Q2",
    body: "typedstandards.org runs a standalone, publisher-agnostic verifier that any host can delegate to. Checks resolve a package's own proofs and re-run them in the reader's browser.",
  },
  {
    title: "Domain-neutral standard",
    state: "built",
    quarter: "2026 Q2",
    body: "The reusable core of the evidence system carries a neutral, cross-sector name: the Typed Standards specification, the shared verification core, and this site. Civic AI Tools is the civic reference implementation.",
  },
  {
    title: "Public specification",
    state: "designed",
    body: "The full Typed Standards specification exists and is in pre-launch private review. It is not published here yet.",
  },
  {
    title: "Lifecycle model and composite bundles",
    state: "designed",
    body: "An event-history model for the evidence lifecycle, and composite bundles that carry a package and its attestations as one content-addressable artifact — so third-party verifiers need not call a host's separate APIs.",
  },
  {
    title: "User-signed evidence and identity tiers",
    state: "upcoming",
    body: "Moving from platform-signed to user-signed evidence with multi-signer attestations, and surfacing identity-strength tiers so readers can calibrate for themselves.",
  },
  {
    title: "Packages that travel",
    state: "upcoming",
    body: "Interoperability extensions and registry federation, advanced only as real adopters need them — a package should remain verifiable wherever it ends up.",
  },
  {
    title: "Formal public RFC",
    state: "upcoming",
    body: "live and in real use — reference implementation + one external adopter — formal public RFC review to follow, no date.",
  },
];

export default function RoadmapPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Roadmap
      </p>
      <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">
        Where the standard stands
      </h1>
      <p className="mt-4 max-w-2xl leading-relaxed text-muted">
        Milestones for the Typed Standards work, at quarter granularity. They
        mirror the public roadmap of{" "}
        <a
          href="https://civicaitools.org"
          target="_blank"
          rel="noopener noreferrer"
          className="underline decoration-dotted hover:text-accent"
        >
          Civic AI Tools
        </a>
        , the civic reference implementation of Typed Standards.
      </p>

      {/* Build-state legend — shared vocabulary with civicaitools.org */}
      <dl className="mt-8 grid gap-4 rounded-md border border-border bg-surface p-5 text-sm sm:grid-cols-3">
        <LegendEntry state="built" definition="Implemented and exercised in production." />
        <LegendEntry state="designed" definition="A spec, decision record, or detailed plan exists; not yet built." />
        <LegendEntry state="upcoming" definition="Identified and scoped in concept; no committed horizon." />
      </dl>

      <ol className="mt-10 space-y-8">
        {MILESTONES.map((m) => (
          <li key={m.title} className="border-t border-border pt-6">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <h2 className="font-display text-lg font-semibold">{m.title}</h2>
              <StateChip state={m.state} />
              {m.quarter && (
                <span className="font-mono text-xs text-muted">{m.quarter}</span>
              )}
            </div>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted">
              {m.body}
            </p>
          </li>
        ))}
      </ol>

      {/* Colophon */}
      <div className="mt-16 border-t border-border pt-6 text-xs leading-relaxed text-muted">
        <p>
          Typed Standards is built by{" "}
          <a
            href="https://nathanstorey.com"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-accent"
          >
            Nathan Storey
          </a>{" "}
          as a personal open-source project. This project is not affiliated
          with, endorsed by, or representative of Nathan&apos;s employer, the
          City of New York, or any government agency.
          {SPONSOR_LINE && <> {SPONSOR_LINE}</>}
        </p>
      </div>
    </div>
  );
}

function StateChip({ state }: { state: BuildState }) {
  const { dot, label } = STATE_STYLE[state];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-border px-2.5 py-0.5 font-mono text-xs text-muted">
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} aria-hidden />
      {label}
    </span>
  );
}

function LegendEntry({
  state,
  definition,
}: {
  state: BuildState;
  definition: string;
}) {
  return (
    <div>
      <dt>
        <StateChip state={state} />
      </dt>
      <dd className="mt-1.5 text-muted">{definition}</dd>
    </div>
  );
}
