import type { Metadata } from "next";
import { verifyEvidence } from "@typedstandards/verify-core";
import verifyCorePkg from "@typedstandards/verify-core/package.json";

export const metadata: Metadata = {
  title: "Verify",
  description:
    "Independently verify a Typed Standards evidence package — by hash, hosted URL, or uploaded bundle.",
};

// Prove the workspace dependency resolves and its built ESM links at build time.
// The real verification flow (resolve proofs → recompute → show the math) is the
// next phase; this confirms the core the page will drive is wired in.
const coreReady = typeof verifyEvidence === "function";

const MODES = [
  {
    name: "Package hash",
    example: "3fb75453…a09f",
    independence:
      "Verify-yourself, but the package is fetched from its publisher's commitment endpoint.",
  },
  {
    name: "Hosted URL",
    example: "https://…/evidence/…",
    independence:
      "Verify-yourself, but the package and trust registry are fetched from the URLs it names.",
  },
  {
    name: "Uploaded bundle",
    example: "evidence-bundle.json",
    independence:
      "Fully offline — every proof is read from the artifact you provide. Nothing is fetched.",
  },
];

export default function VerifyPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Independent verifier
      </p>
      <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">
        Verify an evidence package
      </h1>
      <p className="mt-4 max-w-2xl leading-relaxed text-muted">
        Paste a package hash or a hosted URL, or drop in a bundle. The verifier
        resolves the package&apos;s own proofs and re-checks them here, in your
        browser — recomputing the hash, checking the signature, and looking up the
        signing key in the published trust registry.
      </p>

      {/* Disabled preview of the input — wired up in the next phase. */}
      <div className="mt-8 rounded-lg border border-border bg-surface p-4">
        <label
          htmlFor="verify-input"
          className="block text-sm font-medium text-foreground"
        >
          Hash, URL, or bundle
        </label>
        <div className="mt-2 flex gap-2">
          <input
            id="verify-input"
            type="text"
            disabled
            placeholder="Paste a package hash or URL… (coming soon)"
            className="flex-1 rounded-md border border-border bg-white px-3 py-2 text-sm text-muted disabled:cursor-not-allowed disabled:opacity-70"
          />
          <button
            type="button"
            disabled
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-white opacity-60 disabled:cursor-not-allowed"
          >
            Verify
          </button>
        </div>
        <p className="mt-3 text-xs text-muted">
          Input auto-detection and the live &ldquo;show the math&rdquo; checks
          land in the next phase.
        </p>
      </div>

      {/* The three modes and their honest independence guarantee. */}
      <section className="mt-12">
        <h2 className="font-display text-lg font-semibold">
          Three ways to verify
        </h2>
        <p className="mt-1 text-sm text-muted">
          The guarantee differs by mode — the verifier is honest about what it
          fetches versus what it checks fully offline.
        </p>
        <ul className="mt-5 space-y-3">
          {MODES.map((mode) => (
            <li
              key={mode.name}
              className="rounded-lg border border-border p-4"
            >
              <div className="flex items-baseline justify-between gap-4">
                <span className="font-medium">{mode.name}</span>
                <span className="font-mono text-xs text-muted">
                  {mode.example}
                </span>
              </div>
              <p className="mt-1.5 text-sm text-muted">{mode.independence}</p>
            </li>
          ))}
        </ul>
      </section>

      <p className="mt-12 border-t border-border pt-6 text-xs text-muted">
        Powered by{" "}
        <code className="font-mono">@typedstandards/verify-core</code> v
        {verifyCorePkg.version}
        {coreReady ? " · core ready" : " · core unavailable"}. Disclosure ≠
        validation: this surfaces integrity, identity, timestamp, and
        transparency — not whether the content is correct.
      </p>
    </div>
  );
}
