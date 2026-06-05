import type { Metadata } from "next";
import Link from "next/link";
import { Verifier } from "@/components/Verifier";

type Params = Promise<{ hash: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { hash } = await params;
  const short = hash.slice(0, 12);
  return {
    title: `Verify ${short}…`,
    description: `Independent verification of evidence package ${short}… — checks run in your browser.`,
  };
}

export default async function VerifyHashPage({ params }: { params: Params }) {
  const { hash } = await params;

  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Independent verifier
      </p>
      <h1 className="mt-4 break-all font-display text-2xl font-semibold tracking-tight">
        Verifying{" "}
        <span className="font-mono text-xl">{hash.slice(0, 16)}…</span>
      </h1>
      <p className="mt-3 text-sm text-muted">
        Resolving this package&apos;s proofs and re-checking them in your browser.{" "}
        <Link href="/verify" className="underline decoration-dotted hover:text-accent">
          Verify a different package
        </Link>
        .
      </p>

      <div className="mt-8">
        <Verifier initialInput={hash} autoStart />
      </div>
    </div>
  );
}
