import type { Metadata } from "next";

import { CONSORTIUM_MEMBERS } from "@/lib/consortium";

export const metadata: Metadata = {
  title: "Consortium",
  description:
    "Founding members of the consortium supporting the Typed Standards ecosystem.",
};

export default function ConsortiumPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Consortium
      </p>
      <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">
        Supporting the standard
      </h1>
      <p className="mt-4 max-w-2xl leading-relaxed text-muted">
        Founding members of the consortium supporting the Typed Standards
        ecosystem.
      </p>

      <ul className="mt-10 space-y-8">
        {CONSORTIUM_MEMBERS.map((member) => (
          <li
            key={member.name}
            className="flex flex-col gap-4 border-t border-border pt-6 sm:flex-row sm:gap-8"
          >
            <div className="flex h-12 w-[150px] shrink-0 items-center">
              {member.logoSrc ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img
                  src={member.logoSrc}
                  alt={`${member.name} logo`}
                  className="max-h-10 max-w-[150px] object-contain object-left"
                />
              ) : (
                <div aria-hidden className="h-10 w-32 rounded bg-surface-2" />
              )}
            </div>
            <div className="min-w-0">
              <h2 className="font-display text-lg font-semibold">
                {member.url ? (
                  <a
                    href={member.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-accent"
                  >
                    {member.name}
                  </a>
                ) : (
                  member.name
                )}
              </h2>
              <p className="mt-1 font-mono text-xs uppercase tracking-[0.15em] text-muted">
                {member.role}
              </p>
              <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted">
                {member.blurb}
              </p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
