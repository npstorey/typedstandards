import type { Metadata } from "next";
import verifyCorePkg from "@typedstandards/verify-core/package.json";
import { Verifier } from "@/components/Verifier";

export const metadata: Metadata = {
  title: "Verify",
  description:
    "Independently verify a Typed Standards evidence package — by hash, hosted URL, or uploaded bundle. The checks run in your browser.",
};

function first(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

export default async function VerifyPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  // Badge deep-link (Phase E) passes ?url=; ?hash= is also accepted.
  const initial = first(sp.url) ?? first(sp.hash) ?? "";

  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Independent verifier
      </p>
      <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">
        Verify an evidence package
      </h1>
      <p className="mt-4 max-w-2xl leading-relaxed text-muted">
        Paste a package hash or slug, a hosted URL, or drop in a bundle. The
        verifier resolves the package&apos;s own proofs and re-checks them here, in
        your browser — recomputing the hash, checking the signature, and looking up
        the signing key in the publisher&apos;s trust registry. Each check shows the
        values it computed. You get two independent readings: whether the
        cryptography holds, and — separately — whether the publisher is one
        typedstandards.org recognizes.
      </p>

      <div className="mt-8">
        <Verifier initialInput={initial} autoStart={Boolean(initial)} />
      </div>

      <p className="mt-12 border-t border-border pt-6 text-xs leading-relaxed text-muted">
        Powered by{" "}
        <code className="font-mono">@typedstandards/verify-core</code> v
        {verifyCorePkg.version} — the same verification core civicaitools.org runs
        server-side. Depth matches that core: full client-side crypto for the
        signature, hashes, and key trust; presence for the RFC 3161 timestamp;
        hash-parity for the Rekor transparency log. Disclosure ≠ validation: this
        surfaces integrity, identity, timestamp, and transparency — not whether the
        content is correct.
      </p>
    </div>
  );
}
