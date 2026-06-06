import type { Metadata } from "next";
import Link from "next/link";
import { BadgeBuilder } from "@/components/BadgeBuilder";

export const metadata: Metadata = {
  title: "Embed a verify badge",
  description:
    "Add a “Verify with Typed Standards” badge to your evidence pages. It deep-links readers to the independent verifier, where the checks run in their own browser.",
};

export default function BadgePage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Embeddable verify badge
      </p>
      <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">
        Let readers verify your evidence — independently
      </h1>
      <p className="mt-4 max-w-2xl leading-relaxed text-muted">
        Drop a badge on any page that publishes an evidence package. It deep-links to
        the{" "}
        <Link href="/verify" className="underline decoration-dotted hover:text-accent">
          independent verifier
        </Link>
        , which resolves the package&apos;s own proofs and re-checks them in the
        reader&apos;s browser. The badge is a call to action — the verdict appears on
        the verifier, never on your page.
      </p>

      <div className="mt-8">
        <BadgeBuilder />
      </div>

      <p className="mt-12 border-t border-border pt-6 text-xs leading-relaxed text-muted">
        The badge is a plain image wrapped in a link, so it runs none of our code on
        your page. Prefer the <span className="font-mono">?url=</span> form (a hosted
        commitment or detail URL) — it works for any publisher, not just the default
        host. See the <Link href="/verify" className="underline decoration-dotted hover:text-accent">verifier</Link>{" "}
        for what each check means.
      </p>
    </div>
  );
}
