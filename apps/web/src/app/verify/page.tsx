import type { Metadata } from "next";
import Link from "next/link";
import verifyCorePkg from "@typedstandards/verify-core/package.json";
import { DEFAULT_HOST, parseHostHint } from "@/lib/verify-flow";
import { Verifier } from "@/components/Verifier";

export const metadata: Metadata = {
  title: "Verify",
  description:
    "Independently verify a Typed Standards record package — by hash, hosted URL, or uploaded bundle. The checks run in your browser.",
};

function first(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

/** The bare-identifier anchor as a bare hostname, for prose. Read from the flow's
 *  own constant so this copy cannot drift from what the verifier resolves against. */
const anchorHost = (() => {
  try {
    return new URL(DEFAULT_HOST).host;
  } catch {
    return DEFAULT_HOST;
  }
})();

export default async function VerifyPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  // Badge deep-link (Phase E) passes ?url=; ?hash= is also accepted.
  const initial = first(sp.url) ?? first(sp.hash) ?? "";
  // OPTIONAL origin hint beside ?hash= (typedstandards#58). A bare identifier has no
  // origin, so without a hint it resolves against the declared anchor — correct for
  // the anchor's own readers, one picker click away for everybody else. `host=` lets
  // a link close that gap directly, in the one documented form
  // `host=https://<publisher-host>`; `parseHostHint` delegates every rejection and
  // the #50 www-normalization to `parseHostSegment`, so this entry point and
  // `/verify/<host>/<id>` share one grammar.
  //
  // A hint that does not parse yields `undefined`, and the Verifier then falls back
  // to the anchor and renders the same disclosure line a bare ?hash= gets today: an
  // unreadable hint changes nothing and never reaches resolution. Passed through
  // unconditionally because `initialHost` is consulted only for inputs with no
  // origin of their own — a bare identifier, or a stored-package URL — which is the
  // same set the host picker already governs.
  const hintedHost = parseHostHint(first(sp.host) ?? "");

  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Independent verifier
      </p>
      <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">
        Verify a record package
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
      <p className="mt-4 max-w-2xl text-sm leading-relaxed text-muted">
        A hash or slug carries no origin of its own, so it resolves against{" "}
        {anchorHost} by default. A link can point it at a different publisher in three
        ways: the path form{" "}
        <code className="font-mono">/verify/&lt;host&gt;/&lt;id&gt;</code>, a{" "}
        <code className="font-mono">&amp;host=https://&lt;publisher-origin&gt;</code>{" "}
        parameter beside <code className="font-mono">?hash=</code>, or{" "}
        <code className="font-mono">?url=</code> with the package&apos;s own hosted
        URL. When nothing names a publisher, the verifier states which host answered
        and offers the roster to re-resolve it elsewhere in one click.
      </p>

      <div className="mt-8">
        <Verifier
          initialInput={initial}
          initialHost={hintedHost}
          autoStart={Boolean(initial)}
        />
      </div>

      <p className="mt-12 border-t border-border pt-6 text-xs leading-relaxed text-muted">
        Powered by{" "}
        <code className="font-mono">@typedstandards/verify-core</code> v
        {verifyCorePkg.version} — the same verification core civicaitools.org runs
        server-side. Depth matches that core: full client-side crypto for the
        signature, hashes, and key trust; the RFC 3161 timestamp is chain-verified
        offline to the pinned FreeTSA root; and the Rekor transparency-log entry has
        its Merkle inclusion proof recomputed against the log’s signed checkpoint.
        Disclosure ≠ validation: this surfaces integrity, identity, timestamp, and
        transparency — not whether the content is correct.
      </p>
      <p className="mt-3 text-xs leading-relaxed text-muted">
        Publishing records?{" "}
        <Link href="/badge" className="underline decoration-dotted hover:text-accent">
          Embed a verify badge
        </Link>{" "}
        that deep-links readers here.
      </p>
    </div>
  );
}
