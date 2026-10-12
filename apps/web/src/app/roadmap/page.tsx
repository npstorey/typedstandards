import type { Metadata } from "next";
import type { ReactNode } from "react";
import { SPECIFICATION } from "@/lib/site-config";

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
  body: ReactNode;
};

/**
 * The standard's own milestones: the standard is the product, and Civic AI
 * Tools, its civic reference implementation, is its first domain and keeps
 * its own roadmap. Each built row is backed by a package release on npm or
 * PyPI, or a specification tag. Quarter granularity only on this public page.
 */
const MILESTONES: Milestone[] = [
  {
    title: "Signed record packages",
    state: "built",
    quarter: "2026 Q2",
    body: "Analyses publish as content-addressable, cryptographically signed record packages — Ed25519 signatures over canonical JSON, RFC 3161 timestamps, and a public transparency-log entry for every publish.",
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
    body: "The reusable core of the system for publishing and verifying signed records carries a neutral, cross-sector name: the Typed Standards specification, the shared verification core, and this site. Civic AI Tools is the civic reference implementation.",
  },
  {
    title: "Public specification",
    state: "built",
    quarter: "2026 Q3",
    body: (
      <>
        The{" "}
        <a
          href={SPECIFICATION.url}
          target="_blank"
          rel="noopener noreferrer"
          className="underline decoration-dotted hover:text-accent"
        >
          Typed Standards Specification
        </a>{" "}
        is public: a v0.1 working draft, open for external review, under CC
        BY 4.0. Seven revisions were tagged in the quarter, v0.1.4 through{" "}
        {SPECIFICATION.version}.
      </>
    ),
  },
  {
    title: "Lifecycle model and composite bundles",
    state: "built",
    quarter: "2026 Q3",
    body: "A record's lifecycle is a chain of signed events — withdrawn, reinstated, superseded, revised — that its bundle carries with the record. The verifier reads the status from that chain, counting an event only when its key is bound to the record's signer, and checks a bundle offline.",
  },
  {
    title: "Author-held keys and third-party attestations",
    state: "built",
    quarter: "2026 Q3",
    body: "A record can be signed with a key its author holds, named by a self-certifying did:key, with no registry needed. Anyone with a bound key can sign an attestation that corroborates or contradicts another's record. The verifier states each signing key's trust status, from self-certified to listed in a registry the record names.",
  },
  {
    title: "Deterministic-output profile",
    state: "built",
    quarter: "2026 Q3",
    body: "The scripted-recomputation Producer Profile records a script's run over deterministic tool output, and raw-bytes/v1 hashes a file's exact bytes (specification v0.1.9). A public AI benchmark evaluation run is signed under it as a worked example.",
  },
  {
    title: "Command line",
    state: "built",
    quarter: "2026 Q3",
    body: "@typedstandards/cli signs, views and verifies records from a terminal, and signs withdrawals and attestations. It verifies each record offline before printing it.",
  },
  {
    title: "Host library and template",
    state: "built",
    quarter: "2026 Q3",
    body: "@typedstandards/host-core builds what a static host serves — each record's bundle, the signing key and an index — and checks it. A template repository serves signed records from GitHub Pages with it.",
  },
  {
    title: "Python and notebook publishing",
    state: "built",
    quarter: "2026 Q4",
    body: "The typedstandards package on PyPI signs, views and verifies records from Python, and publishes a record from a notebook to a GitHub Pages host as one commit.",
  },
  {
    title: "Graded identity",
    state: "upcoming",
    body: "Signers bound to an identity above the pseudonymous rung — an OAuth account, an academic identifier, an institution's domain, a notary — surfaced as signals a reader can filter on, as the specification's identity ladder defines.",
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
        Milestones for the Typed Standards work, at quarter granularity.{" "}
        <a
          href="https://civicaitools.org/roadmap"
          target="_blank"
          rel="noopener noreferrer"
          className="underline decoration-dotted hover:text-accent"
        >
          Civic AI Tools
        </a>
        , the civic reference implementation and the standard&apos;s first
        domain, keeps its own roadmap.
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
