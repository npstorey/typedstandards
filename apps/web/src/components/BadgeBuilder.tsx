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

// A working example so the page is illustrative on load; the user replaces it.
const EXAMPLE = "median-household-income-for-manhattan-255b8e";

/** The embed builder: paste a package URL/hash/slug → live WYSIWYG badge preview
 *  (same-origin, so a preview deployment shows its own asset) + copy-paste HTML and
 *  Markdown snippets (canonical origin, so they work when pasted on any host). The
 *  badge is a call to action, never a verdict — restated on the page. */
export function BadgeBuilder() {
  const [input, setInput] = useState(EXAMPLE);
  const [theme, setTheme] = useState<BadgeTheme>("light");
  const [copied, setCopied] = useState<"html" | "md" | null>(null);

  const kind = classifyBadgeInput(input);
  const ready = kind === "url" || kind === "hash";

  // Preview uses a same-origin (relative) asset + link, so a preview deployment is
  // WYSIWYG. The copied snippet uses the canonical production origin.
  const previewSrc = badgeAssetUrl("", theme);
  const previewHref = ready ? buildVerifyHref("", input) : "/verify";
  const html = buildEmbedHtml(CANONICAL_ORIGIN, input, theme);
  const md = buildEmbedMarkdown(CANONICAL_ORIGIN, input, theme);

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
          placeholder="https://…/api/evidence/<id>/commitment — or a 64-char hash / slug"
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
            <span>Hosted URL — works for any publisher (host-independent).</span>
          )}
          {kind === "hash" && (
            <span>Hash or slug — resolved against the default host (civicaitools.org).</span>
          )}
          {kind === "bundle" && (
            <span style={{ color: "var(--trust-attention)" }}>
              A badge links to a resolvable URL or hash — not a pasted bundle.
            </span>
          )}
          {kind === "empty" && <span>Paste a package URL, hash, or slug to build a badge.</span>}
        </div>
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
            Links to <span className="font-mono">{CANONICAL_ORIGIN}{buildVerifyHref("", input)}</span>
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
