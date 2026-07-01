import Link from "next/link";
import { EXPRESS_INTEREST_URL } from "@/lib/site-config";

export default function Home() {
  return (
    <div className="mx-auto max-w-5xl px-6">
      {/* Hero */}
      <section className="py-20 sm:py-28">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
          Verifiable evidence
        </p>
        <h1 className="mt-4 max-w-3xl font-display text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
          A standard for signed evidence you can verify yourself.
        </h1>
        <p className="mt-6 max-w-2xl text-lg leading-relaxed text-muted">
          Typed Standards defines a format for publishing AI-generated answers
          as evidence packages that carry their own cryptographic proof — a
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
          <a
            href="https://civicaitools.org"
            target="_blank"
            rel="noopener noreferrer"
            className="underline decoration-dotted hover:text-accent"
          >
            Civic AI Tools
          </a>{" "}
          is the civic reference implementation of Typed Standards. See the{" "}
          <Link
            href="/roadmap"
            className="underline decoration-dotted hover:text-accent"
          >
            roadmap
          </Link>{" "}
          for where the standard stands.
        </p>
      </section>

      {/* Honest scope note */}
      <section className="border-t border-border py-12">
        <p className="max-w-2xl text-sm leading-relaxed text-muted">
          Verification surfaces <strong className="text-foreground">integrity,
          identity, timestamp, and transparency</strong> — whether a package is
          intact and who signed it. It does <em>not</em> judge whether the
          content is correct. The full specification is in pre-launch review and
          is not published here yet.
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
