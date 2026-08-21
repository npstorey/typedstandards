import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { parseVerifyTarget } from "@/lib/verify-flow";
import { Verifier } from "@/components/Verifier";

// The verifier's short-link route, at BOTH depths (#44 B7):
//
//   /verify/<id>          — resolve <id> against the directory's declared anchor
//   /verify/<host>/<id>   — resolve <id> against https://<host>
//
// A CATCH-ALL rather than a `[hash]` + `[host]/[id]` pair, for two reasons. Next.js
// forbids two differently-named dynamic segments at one path level, so the two
// depths cannot be separate route files unless the first segment is given a single
// name that means "id" at depth 1 and "host" at depth 2 — a param whose meaning
// depends on how deep you are. And keeping both depths in one handler puts the whole
// path contract in one place: `parseVerifyTarget` decides, and its round-trip with
// `deriveShareTarget` is unit-tested without Next in the loop.
//
// `/verify` itself is unaffected: a required catch-all does not match zero segments,
// so it still renders the sibling `verify/page.tsx`. Anything deeper than two
// segments, or a malformed host, is a 404 rather than a silently-reinterpreted link.

type Params = Promise<{ target: string[] }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { target } = await params;
  const parsed = parseVerifyTarget(target);
  if (!parsed) return { title: "Verify" };
  const short = parsed.id.slice(0, 12);
  const on = parsed.host ? ` on ${hostLabel(parsed.host)}` : "";
  return {
    title: `Verify ${short}…`,
    description: `Independent verification of record package ${short}…${on} — checks run in your browser.`,
  };
}

export default async function VerifyTargetPage({ params }: { params: Params }) {
  const { target } = await params;
  const parsed = parseVerifyTarget(target);
  if (!parsed) notFound();

  const { id, host } = parsed;

  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Independent verifier
      </p>
      <h1 className="mt-4 break-all font-display text-2xl font-semibold tracking-tight">
        Verifying <span className="font-mono text-xl">{id.slice(0, 16)}…</span>
      </h1>
      <p className="mt-3 text-sm text-muted">
        Resolving this package&apos;s proofs and re-checking them in your browser.{" "}
        <Link href="/verify" className="underline decoration-dotted hover:text-accent">
          Verify a different package
        </Link>
        .
      </p>

      <div className="mt-8">
        <Verifier initialInput={id} initialHost={host} autoStart />
      </div>
    </div>
  );
}

/** `https://example.org` → `example.org`, for prose. */
function hostLabel(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}
