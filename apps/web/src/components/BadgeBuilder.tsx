"use client";

import { useState } from "react";
import {
  BADGE_ALT,
  BADGE_HEIGHT,
  BADGE_WIDTH,
  CANONICAL_ORIGIN,
  badgeAssetUrl,
  buildEmbedHtml,
  buildEmbedMarkdown,
  buildVerifyHref,
  classifyBadgeInput,
  type BadgeTheme,
} from "@/lib/badge-asset";
// Imported from host-directory, NOT verify-flow: this page has no reason to pull the
// verification core into its bundle (see badge-asset.ts's dependency-free note).
// `parseHostHint` is the SAME function `/verify` reads the `host=` parameter with —
// it lives in host-directory precisely so this page can validate an origin without
// crossing that line, and so the emitter and the reader cannot drift apart.
import { BARE_ID_ANCHOR, parseHostHint } from "@/lib/host-directory";

// A working example so the page is illustrative on load; the user replaces it.
const EXAMPLE = "median-household-income-for-manhattan-255b8e";

/** The bare-identifier anchor as a bare hostname, for prose. */
const anchorHost = (() => {
  try {
    return new URL(BARE_ID_ANCHOR).host;
  } catch {
    return BARE_ID_ANCHOR;
  }
})();

/** The embed builder: paste a package URL/hash/slug → live WYSIWYG badge preview
 *  (same-origin, so a preview deployment shows its own asset) + copy-paste HTML and
 *  Markdown snippets (canonical origin, so they work when pasted on any host). The
 *  badge is a call to action, never a verdict — restated on the page. */
export function BadgeBuilder() {
  const [input, setInput] = useState(EXAMPLE);
  const [hostHint, setHostHint] = useState("");
  const [theme, setTheme] = useState<BadgeTheme>("light");
  const [copied, setCopied] = useState<"html" | "md" | null>(null);

  const kind = classifyBadgeInput(input);
  const ready = kind === "url" || kind === "hash";

  // The optional publisher-origin hint (typedstandards#58), offered ONLY for a bare
  // hash or slug: a URL input already carries an origin, and a bundle is not
  // badgeable. FREE TEXT, never a roster dropdown — the publishers who need the hint
  // are exactly the ones not (yet) listed, and the shape grammar has never consulted
  // the roster (see parseHostSegment). `undefined` — blank, or a value that does not
  // parse — emits no `&host=`, leaving the link byte-identical to what this builder
  // produces today.
  const hintOrigin = kind === "hash" ? parseHostHint(hostHint) : undefined;
  const hintRejected = kind === "hash" && hostHint.trim() !== "" && !hintOrigin;

  // Preview uses a same-origin (relative) asset + link, so a preview deployment is
  // WYSIWYG. The copied snippet uses the canonical production origin.
  const previewSrc = badgeAssetUrl("", theme);
  const previewHref = ready ? buildVerifyHref("", input, hintOrigin) : "/verify";
  const html = buildEmbedHtml(CANONICAL_ORIGIN, input, theme, hintOrigin);
  const md = buildEmbedMarkdown(CANONICAL_ORIGIN, input, theme, hintOrigin);

  const copy = (text: string, which: "html" | "md") => {
    void navigator.clipboard?.writeText(text);
    setCopied(which);
    window.setTimeout(() => setCopied((c) => (c === which ? null : c)), 1500);
  };

  return (
    <div className="space-y-8">
      {/* Input */}
      <div className="rounded-lg border border-border bg-surface p-4">
        <label htmlFor="badge-input" className="block text-sm font-medium">
          Package URL, hash, or slug
        </label>
        <input
          id="badge-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          spellCheck={false}
          placeholder="https://…/api/records/<id>/commitment — or a 64-char hash / slug"
          className="mt-2 w-full rounded-md border border-border bg-white px-3 py-2 font-mono text-sm outline-none focus:border-accent"
        />
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-muted">
          <span>
            Links via{" "}
            <span className="font-mono text-foreground">
              {kind === "url" ? "?url=" : kind === "bundle" ? "—" : "?hash="}
            </span>
          </span>
          {kind === "url" && (
            // A commitment or detail URL carries its publisher's origin. A stored-package
            // URL does not — its origin is object storage — so the verifier resolves the
            // package hash in its filename against the declared anchor (#44 B5).
            <span>
              Hosted URL — works for any publisher. A commitment or detail URL carries
              its publisher&apos;s origin; a stored-package URL names storage, so its
              hash resolves against {anchorHost}.
            </span>
          )}
          {kind === "hash" && (
            // Read from the directory's declared bare-identifier anchor rather than
            // naming a host inline, so this copy cannot drift from what the verifier
            // actually resolves against (#44 B6). The escape hatches are named here
            // because a non-anchor publisher otherwise has no way to learn that its
            // identifier is being resolved somewhere else (typedstandards#58, A).
            <span>
              Hash or slug — carries no origin, so it resolves against{" "}
              {anchorHost}. Add a publisher origin below to carry one, or use the path
              link <span className="font-mono">/verify/&lt;host&gt;/&lt;id&gt;</span>{" "}
              or a <span className="font-mono">?url=</span> link with the
              package&apos;s hosted URL. A reader can also re-resolve it on another
              listed host from the verifier.
            </span>
          )}
          {kind === "bundle" && (
            <span style={{ color: "var(--trust-attention)" }}>
              A badge links to a resolvable URL or hash — not a pasted bundle.
            </span>
          )}
          {kind === "empty" && <span>Paste a package URL, hash, or slug to build a badge.</span>}
        </div>

        {kind === "hash" && (
          <div className="mt-4 border-t border-border pt-4">
            <label htmlFor="badge-host" className="block text-sm font-medium">
              Publisher origin (optional)
            </label>
            <input
              id="badge-host"
              value={hostHint}
              onChange={(e) => setHostHint(e.target.value)}
              spellCheck={false}
              placeholder="https://data-concierge.dathere.com"
              className="mt-2 w-full rounded-md border border-border bg-white px-3 py-2 font-mono text-sm outline-none focus:border-accent"
            />
            <p className="mt-2 text-xs leading-relaxed text-muted">
              Shape-validated only — listing is not required. Leave it blank and the
              link resolves against {anchorHost}.
            </p>
            {hintRejected && (
              <p
                className="mt-1 text-xs leading-relaxed"
                style={{ color: "var(--trust-attention)" }}
              >
                That is not a usable origin, so the link leaves it out. Write the full
                origin with its scheme and nothing more —{" "}
                <span className="font-mono">https://your-host.example</span>, no port
                and no path.
              </p>
            )}
          </div>
        )}
      </div>

      {/* Theme + live preview */}
      <div>
        <div className="flex items-center justify-between">
          <h2 className="font-display text-lg font-semibold">Preview</h2>
          <ThemeToggle theme={theme} onChange={setTheme} />
        </div>
        <div
          className="mt-3 flex flex-col items-center gap-3 rounded-lg border border-border p-8"
          style={{ background: theme === "dark" ? "#0a0a0a" : "var(--surface)" }}
        >
          {ready ? (
            <a href={previewHref} target="_blank" rel="noreferrer" aria-label={BADGE_ALT}>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src={previewSrc} alt={BADGE_ALT} width={BADGE_WIDTH} height={BADGE_HEIGHT} />
            </a>
          ) : (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={previewSrc} alt={BADGE_ALT} width={BADGE_WIDTH} height={BADGE_HEIGHT} />
          )}
        </div>
        {ready && (
          <p className="mt-2 break-all text-xs text-muted">
            Links to{" "}
            <span className="font-mono">
              {CANONICAL_ORIGIN}
              {buildVerifyHref("", input, hintOrigin)}
            </span>
          </p>
        )}
      </div>

      {/* Snippets */}
      <div className="space-y-5">
        <Snippet
          title="HTML"
          code={html}
          disabled={!ready}
          copied={copied === "html"}
          onCopy={() => copy(html, "html")}
        />
        <Snippet
          title="Markdown"
          code={md}
          disabled={!ready}
          copied={copied === "md"}
          onCopy={() => copy(md, "md")}
        />
      </div>

      {/* Honesty note */}
      <p className="rounded-lg border border-border bg-surface p-4 text-xs leading-relaxed text-muted">
        <strong className="text-foreground">The badge is a call to action, not a
        verdict.</strong>{" "}
        It never claims a package is &ldquo;verified&rdquo; on your page — that would be
        a claim it can&rsquo;t back, and a static image anyone could forge. The actual
        result is computed in the reader&rsquo;s own browser when they click through to
        the verifier, and shown only there.
      </p>
    </div>
  );
}

function ThemeToggle({ theme, onChange }: { theme: BadgeTheme; onChange: (t: BadgeTheme) => void }) {
  return (
    <div className="inline-flex rounded-md border border-border p-0.5 text-xs">
      {(["light", "dark"] as const).map((t) => (
        <button
          key={t}
          type="button"
          onClick={() => onChange(t)}
          className={`rounded px-2.5 py-1 font-medium capitalize transition-colors ${
            theme === t ? "bg-accent text-white" : "text-muted hover:text-accent"
          }`}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

function Snippet({
  title,
  code,
  disabled,
  copied,
  onCopy,
}: {
  title: string;
  code: string;
  disabled: boolean;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">{title}</h3>
        <button
          type="button"
          onClick={onCopy}
          disabled={disabled}
          className="rounded-md border border-border px-2.5 py-1 text-xs font-medium hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="mt-2 overflow-auto rounded-md border border-border bg-surface p-3 font-mono text-xs leading-relaxed text-foreground">
        {code}
      </pre>
    </div>
  );
}
