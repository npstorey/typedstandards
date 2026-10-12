import Link from "next/link";
import type { ReactNode } from "react";
import { EXPRESS_INTEREST_URL, SPECIFICATION } from "@/lib/site-config";

type Package = {
  name: string;
  registry: "npm" | "PyPI";
  href: string;
  role: ReactNode;
};

/**
 * The standard's published packages. No version here: each registry page
 * states its current one, so this list does not go stale at a release.
 */
const PACKAGES: Package[] = [
  {
    name: "@typedstandards/verify-core",
    registry: "npm",
    href: "https://www.npmjs.com/package/@typedstandards/verify-core",
    role: "The specification's verification checks, the same in a browser and on a server. This site's verifier runs it.",
  },
  {
    name: "@typedstandards/produce-core",
    registry: "npm",
    href: "https://www.npmjs.com/package/@typedstandards/produce-core",
    role: "Builds and signs records and their attestations, with no I/O of its own.",
  },
  {
    name: "@typedstandards/cli",
    registry: "npm",
    href: "https://www.npmjs.com/package/@typedstandards/cli",
    role: "Signs, views and verifies records from a terminal.",
  },
  {
    name: "@typedstandards/host-core",
    registry: "npm",
    href: "https://www.npmjs.com/package/@typedstandards/host-core",
    role: (
      <>
        Serves signed records from a static site, and checks what it serves.{" "}
        <a
          href="https://host-template.typedstandards.org"
          target="_blank"
          rel="noopener noreferrer"
          className="underline decoration-dotted hover:text-accent"
        >
          A template
        </a>{" "}
        does it on GitHub Pages.
      </>
    ),
  },
  {
    name: "typedstandards",
    registry: "PyPI",
    href: "https://pypi.org/project/typedstandards/",
    role: "Signs a record from Python or a notebook and publishes it to a GitHub Pages site.",
  },
];

export default function Home() {
  return (
    <div className="mx-auto max-w-5xl px-6">
      {/* Hero */}
      <section className="py-20 sm:py-28">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
          Verifiable records
        </p>
        <h1 className="mt-4 max-w-3xl font-display text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
          A standard for signed records you can verify yourself.
        </h1>
        <p className="mt-6 max-w-2xl text-lg leading-relaxed text-muted">
          Typed Standards defines a format for publishing AI-generated answers
          as records — packages that carry their own cryptographic proof: a
          signature, a content hash, and a public trust registry. Anyone can
          check a package independently, without trusting the site that
          produced it.
        </p>
        <div className="mt-9 flex flex-wrap items-center gap-4">
          <Link
            href="/verify"
            className="rounded-md bg-accent px-5 py-3 text-sm font-medium text-white transition-colors hover:bg-accent-ink"
          >
            Verify a package
          </Link>
          <a
            href="https://github.com/npstorey/typedstandards"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm font-medium text-muted hover:text-accent"
          >
            View the source →
          </a>
        </div>
      </section>

      {/* What it is */}
      <section className="grid gap-8 border-t border-border py-16 sm:grid-cols-3">
        <Feature
          title="Signed at the source"
          body="Every package is signed and hashed when it is produced. The signature covers the exact bytes, so any later change is detectable."
        />
        <Feature
          title="Verify independently"
          body="The verifier resolves a package's own proofs and re-checks them in your browser — it doesn't take the publisher's word for it."
        />
        <Feature
          title="Shows the math"
          body="Each check renders as it resolves: the recomputed hash, the signature result, the registry lookup. Integrity and identity — not a claim of correctness."
        />
      </section>

      {/* In plain language */}
      <section className="border-t border-border py-16">
        <h2 className="font-display text-xl font-semibold tracking-tight">
          In plain language
        </h2>
        <p className="mt-4 max-w-2xl leading-relaxed text-muted">
          Typed Standards is an open standard for independent, third-party
          verification of AI-generated answers. It gives someone else a
          cryptographically signed way to confirm that an answer is
          reproducible and verifiable from its inputs — without attesting that
          any specific answer is correct. Standardized provenance and
          reproducibility of AI output give others a baseline to evaluate
          trustworthiness independently, on their own criteria.
        </p>
        <p className="mt-4 max-w-2xl leading-relaxed text-muted">
          See the{" "}
          <Link
            href="/roadmap"
            className="underline decoration-dotted hover:text-accent"
          >
            roadmap
          </Link>{" "}
          for where the standard stands.
        </p>
      </section>

      {/* Use it */}
      <section className="border-t border-border py-16">
        <h2 className="font-display text-xl font-semibold tracking-tight">
          Use it
        </h2>
        <ul className="mt-6 max-w-2xl space-y-5">
          {PACKAGES.map((p) => (
            <li key={p.name}>
              <a
                href={p.href}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono text-sm font-medium hover:text-accent"
              >
                {p.name}
              </a>
              <span className="ml-2 font-mono text-xs text-muted">
                {p.registry}
              </span>
              <p className="mt-1 text-sm leading-relaxed text-muted">
                {p.role}
              </p>
            </li>
          ))}
        </ul>
        <p className="mt-8 max-w-2xl leading-relaxed text-muted">
          <Link
            href="/examples"
            className="underline decoration-dotted hover:text-accent"
          >
            Worked examples
          </Link>
          , each a public repository, show records signed, served and
          verified.
        </p>
        <p className="mt-4 max-w-2xl leading-relaxed text-muted">
          <a
            href="https://civicaitools.org"
            target="_blank"
            rel="noopener noreferrer"
            className="underline decoration-dotted hover:text-accent"
          >
            Civic AI Tools
          </a>{" "}
          is the civic reference implementation and the standard&apos;s first
          domain. Its domain packages are{" "}
          <a
            href="https://www.npmjs.com/package/@typedstandards/civic-typed-harness"
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-sm hover:text-accent"
          >
            @typedstandards/civic-typed-harness
          </a>{" "}
          and{" "}
          <a
            href="https://www.npmjs.com/package/@typedstandards/civic-typed-router"
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-sm hover:text-accent"
          >
            @typedstandards/civic-typed-router
          </a>
          .
        </p>
      </section>

      {/* Honest scope note */}
      <section className="border-t border-border py-12">
        <p className="max-w-2xl text-sm leading-relaxed text-muted">
          Verification surfaces <strong className="text-foreground">integrity,
          identity, timestamp, and transparency</strong> — whether a package is
          intact and who signed it. It does <em>not</em> judge whether the
          content is correct. The{" "}
          <a
            href={SPECIFICATION.url}
            target="_blank"
            rel="noopener noreferrer"
            className="underline decoration-dotted hover:text-accent"
          >
            Typed Standards Specification
          </a>{" "}
          is public: {SPECIFICATION.version}, a working draft open for
          external review, under CC BY 4.0.
        </p>
        <p className="mt-4 max-w-2xl text-sm leading-relaxed text-muted">
          Working on something this could serve, or want to follow along?{" "}
          {/* Entry point reads from EXPRESS_INTEREST_URL — swap the constant
              in src/lib/site-config.ts to re-route every contact link. */}
          <a
            href={EXPRESS_INTEREST_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="underline decoration-dotted hover:text-accent"
          >
            Get in touch
          </a>
          .
        </p>
      </section>
    </div>
  );
}

function Feature({ title, body }: { title: string; body: string }) {
  return (
    <div>
      <h2 className="font-display text-base font-semibold">{title}</h2>
      <p className="mt-2 text-sm leading-relaxed text-muted">{body}</p>
    </div>
  );
}
