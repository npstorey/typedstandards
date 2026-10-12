import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Examples",
  description:
    "Worked examples of Typed Standards: public repositories of signed records, and the sites that serve them.",
};

type Example = {
  title: string;
  body: string;
  /** The site that serves the example's records, when it has one. */
  site?: string;
  repo: string;
};

/**
 * Public, finished examples only, each checked public on GitHub before it
 * was listed. Copy names no outside organization or project.
 */
const EXAMPLES: Example[] = [
  {
    title: "An evaluation run as records",
    body: "A public AI benchmark evaluation run as two signed records: one pins the published log and score, the other recomputes the score from the log's per-sample grades. One command checks both offline.",
    repo: "https://github.com/npstorey/typedstandards-eval-run-example",
  },
  {
    title: "Core and satellite map",
    body: "A map of the standard's technical relations to public projects. Each relation is a signed record served from a static host, and one command checks every record offline.",
    site: "https://core-satellite.typedstandards.org",
    repo: "https://github.com/npstorey/typedstandards-core-satellite-example",
  },
  {
    title: "Host template",
    body: "A template repository that serves signed records from GitHub Pages under your own did:key, with @typedstandards/host-core. Copy it and replace the example record with your own.",
    site: "https://host-template.typedstandards.org",
    repo: "https://github.com/npstorey/typedstandards-host-template",
  },
  {
    title: "Publishing from a notebook",
    body: "Records signed in a hosted notebook and a local notebook app, each published to a GitHub Pages host with one call to the typedstandards Python package. A rerun revises the first record, which is then withdrawn with its reason.",
    site: "https://publish-example.typedstandards.org",
    repo: "https://github.com/npstorey/typedstandards-publish-example",
  },
];

export default function ExamplesPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Examples
      </p>
      <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">
        Worked examples
      </h1>
      <p className="mt-4 max-w-2xl leading-relaxed text-muted">
        Each example is a public repository of signed records. Three also
        serve their records from a site.
      </p>

      <ul className="mt-10 space-y-8">
        {EXAMPLES.map((e) => (
          <li key={e.title} className="border-t border-border pt-6">
            <h2 className="font-display text-lg font-semibold">{e.title}</h2>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted">
              {e.body}
            </p>
            <p className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm font-medium">
              {e.site && (
                <a
                  href={e.site}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-accent hover:text-accent-ink"
                >
                  {new URL(e.site).host} →
                </a>
              )}
              <a
                href={e.repo}
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted hover:text-accent"
              >
                Repository →
              </a>
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
