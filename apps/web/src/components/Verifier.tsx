"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  detectInputMode,
  describeMode,
  identifierResolutionKind,
  resolveInput,
  buildVerifyInput,
  verifyResolved,
  presentVerification,
  buildPreview,
  deriveShareTarget,
  registryMetaOf,
  canRecheckKeyTrust,
  bundleRegistrySetAside,
  recheckKeyTrustLive,
  VerifyFlowError,
  DEFAULT_HOST,
  HOST_DIRECTORY,
  type CheckRow as CheckRowData,
  type HostRecognition,
  type IndependenceNote as IndependenceNoteData,
  type IdentifierResolution,
  type InputMode,
  type KeyTrustRecheck,
  type PagePreview as PreviewData,
  type ResolveStep,
  type ResolvedInput,
  type Verdict,
} from "@/lib/verify-flow";
import type { VerifyResult } from "@typedstandards/verify-core";
import { CheckRow } from "./CheckRow";
import { VerdictBanner } from "./VerdictBanner";
import { RecognitionBanner } from "./RecognitionBanner";
import { PagePreview } from "./PagePreview";

type Phase = "idle" | "resolving" | "verifying" | "revealing" | "done" | "error";

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function Verifier({
  initialInput = "",
  initialHost,
  autoStart = false,
}: {
  initialInput?: string;
  /** The origin a BARE IDENTIFIER resolves against, when the link named one
   *  (`/verify/<host>/<id>`). Absent ⇒ the directory's declared anchor. */
  initialHost?: string;
  autoStart?: boolean;
}) {
  const [raw, setRaw] = useState(initialInput);
  const [host, setHost] = useState<string>(initialHost ?? DEFAULT_HOST);
  const [phase, setPhase] = useState<Phase>("idle");
  const [steps, setSteps] = useState<ResolveStep[]>([]);
  const [rows, setRows] = useState<CheckRowData[]>([]);
  const [revealCount, setRevealCount] = useState(0);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [recognition, setRecognition] = useState<HostRecognition | null>(null);
  const [independence, setIndependence] = useState<IndependenceNoteData | null>(null);
  const [preview, setPreview] = useState<PreviewData | null>(null);
  const [resolved, setResolved] = useState<ResolvedInput | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [recheck, setRecheck] = useState<{
    phase: "idle" | "loading" | "done" | "error";
    data?: KeyTrustRecheck;
    error?: string;
  }>({ phase: "idle" });
  const [sharePath, setSharePath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // `resolveHost` is passed in rather than read from state so a picker click can set
  // the host and kick off the run in the same tick without racing the state update.
  const run = useCallback(async (input: string, resolveHost: string) => {
    const s = input.trim();
    if (!s) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    setPhase("resolving");
    setError(null);
    setSteps([]);
    setRows([]);
    setRevealCount(0);
    setVerdict(null);
    setRecognition(null);
    setIndependence(null);
    setPreview(null);
    setResolved(null);
    setResult(null);
    setRecheck({ phase: "idle" });
    setSharePath(null);
    setCopied(false);

    const mode = detectInputMode(s);
    try {
      const resolvedInput = await resolveInput(
        mode,
        s,
        ac.signal,
        (step) => setSteps((prev) => [...prev, step]),
        // Only consulted for a bare identifier; 'url'/'bundle' carry their own origin.
        { host: resolveHost },
      );
      if (ac.signal.aborted) return;
      setResolved(resolvedInput);

      setPhase("verifying");
      const { input: vinput, result } = await verifyResolved(resolvedInput);
      if (ac.signal.aborted) return;
      setResult(result);

      // The rows, the verdict and the second, independent dimension (Phase D): host
      // recognition, resolved from the declared registry origin + the directory +
      // the SAME key-trust result and registry provenance, kept orthogonal to the
      // cryptographic verdict.
      const presentation = presentVerification(resolvedInput, vinput, result);
      const builtRows = presentation.rows;
      setRows(builtRows);
      setVerdict(presentation.verdict);
      setRecognition(presentation.recognition);
      setIndependence(presentation.independence);
      setPreview(buildPreview(resolvedInput.pkg, resolvedInput.commitment));

      setPhase("revealing");
      for (let i = 1; i <= builtRows.length; i++) {
        if (ac.signal.aborted) return;
        setRevealCount(i);
        await delay(160);
      }
      if (ac.signal.aborted) return;
      setPhase("done");

      // Shareable result link — rebuilt from the URL that actually resolved (200),
      // never from `packageHash` (the slug-indexed endpoint 404s on a raw hash).
      const nextSharePath = deriveShareTarget(resolvedInput);
      if (nextSharePath) {
        setSharePath(nextSharePath);
        if (typeof window !== "undefined") {
          window.history.replaceState(null, "", nextSharePath);
        }
      }
    } catch (e) {
      if (ac.signal.aborted) return;
      setError(
        e instanceof VerifyFlowError || e instanceof Error ? e.message : String(e),
      );
      setPhase("error");
    }
  }, []);

  useEffect(() => {
    if (!autoStart || !initialInput.trim()) return;
    // Defer the kickoff out of the synchronous effect body so the first setState
    // doesn't cascade a render during commit; the deep-link runs on next tick.
    const id = setTimeout(() => void run(initialInput, initialHost ?? DEFAULT_HOST), 0);
    return () => clearTimeout(id);
    // run is stable; only fire for the initial deep-link.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onFile = async (file: File) => {
    const text = await file.text();
    setRaw(text);
    void run(text, host);
  };

  /** Roster-driven "try another host": re-resolve the SAME bare identifier against a
   *  different publisher. */
  const onPickHost = useCallback(
    (next: string) => {
      setHost(next);
      void run(raw, next);
    },
    [raw, run],
  );

  // Online recheck (#119 P4): re-run the registry-dependent checks against the
  // LIVE registry, closing the offline-revocation gap a carried snapshot leaves. A
  // completed re-check re-reads #5, the headline and recognition (#93 item 3); one
  // that cannot run throws, and nothing on the page changes.
  const onRecheck = useCallback(async () => {
    if (!resolved || !result) return;
    setRecheck({ phase: "loading" });
    try {
      // The same verify-core input the verdict was computed from (see `run`).
      const vinput = buildVerifyInput(resolved.commitment, resolved.pkg, {
        offline: resolved.fullyOffline,
      });
      const data = await recheckKeyTrustLive(resolved.commitment, result, vinput);
      const shown = presentVerification(resolved, vinput, result, data);
      setRows(shown.rows);
      setVerdict(shown.verdict);
      setRecognition(shown.recognition);
      setIndependence(shown.independence);
      setRecheck({ phase: "done", data });
    } catch (e) {
      setRecheck({ phase: "error", error: e instanceof Error ? e.message : String(e) });
    }
  }, [resolved, result]);

  const running = phase === "resolving" || phase === "verifying" || phase === "revealing";
  const mode: InputMode = detectInputMode(raw);
  // Set when this input has no publisher origin of its own — a bare hash/slug, OR a
  // package-blob URL, whose origin names storage rather than a publisher (#44 B5).
  const identifierResolution = identifierResolutionKind(mode, raw);

  return (
    <div>
      {/* Input */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run(raw, host);
        }}
        className="rounded-lg border border-border bg-surface p-4"
      >
        <label htmlFor="verify-input" className="block text-sm font-medium">
          Hash, URL, or bundle
        </label>
        <textarea
          id="verify-input"
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !raw.includes("\n")) {
              e.preventDefault();
              void run(raw, host);
            }
          }}
          rows={raw.includes("\n") ? 6 : 1}
          spellCheck={false}
          placeholder="Paste a 64-char package hash, a record slug, a hosted URL, or a bundle JSON…"
          className="mt-2 w-full resize-y rounded-md border border-border bg-white px-3 py-2 font-mono text-sm outline-none focus:border-accent"
        />
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 text-xs text-muted">
            <span>
              Detected:{" "}
              <span className="font-medium text-foreground">
                {raw.trim() ? describeMode(mode, raw) : "—"}
              </span>
            </span>
            <label className="cursor-pointer underline decoration-dotted hover:text-accent">
              upload a bundle
              <input
                type="file"
                accept="application/json,.json"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void onFile(f);
                }}
              />
            </label>
          </div>
          <button
            type="submit"
            disabled={running || !raw.trim()}
            className="rounded-md bg-accent px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-ink disabled:cursor-not-allowed disabled:opacity-50"
          >
            {running ? "Verifying…" : "Verify"}
          </button>
        </div>
        {identifierResolution && (
          <IdentifierResolutionNote
            kind={identifierResolution}
            host={host}
            onPick={onPickHost}
            disabled={running}
          />
        )}
      </form>

      {/* Results */}
      {phase !== "idle" && (
        <section className="mt-8 space-y-5">
          {error ? (
            <div
              className="rounded-lg border p-4 text-sm"
              style={{ borderColor: "var(--trust-alarm)", color: "var(--trust-alarm)" }}
            >
              <p className="font-medium">Could not verify</p>
              <p className="mt-1 text-foreground">{error}</p>
            </div>
          ) : (
            <>
              {phase === "done" && verdict && (
                <div className="space-y-3">
                  <VerdictBanner verdict={verdict} />
                  {recognition && <RecognitionBanner recognition={recognition} />}
                </div>
              )}

              {running && (
                <p className="text-sm text-muted" aria-live="polite">
                  {phase === "resolving" && "Resolving package & proofs…"}
                  {phase === "verifying" && "Running the §9.2 checks in your browser…"}
                  {phase === "revealing" && `Showing the math… (${revealCount}/${rows.length})`}
                </p>
              )}

              {steps.length > 0 && <ResolutionSteps steps={steps} />}

              {rows.length > 0 && (
                <ol className="space-y-3">
                  {rows.map((r, i) => (
                    <CheckRow
                      key={r.num}
                      row={r}
                      revealed={phase === "done" || i < revealCount}
                    />
                  ))}
                </ol>
              )}

              {phase === "done" &&
                resolved &&
                result &&
                canRecheckKeyTrust(registryMetaOf(resolved), result) && (
                  <KeyTrustRecheckPanel
                    state={recheck}
                    onRecheck={onRecheck}
                    registryHost={hostOf(registryMetaOf(resolved).url)}
                    bundleStatus={result.keyTrust?.status}
                    setAside={bundleRegistrySetAside(registryMetaOf(resolved), result)}
                  />
                )}

              {phase === "done" && independence && <IndependenceNote note={independence} />}

              {phase === "done" && preview && <PagePreview preview={preview} />}

              {phase === "done" && sharePath && (
                <ShareLink path={sharePath} copied={copied} onCopy={() => {
                  const url = `${window.location.origin}${sharePath}`;
                  void navigator.clipboard?.writeText(url);
                  setCopied(true);
                }} />
              )}
            </>
          )}
        </section>
      )}
    </div>
  );
}

/**
 * The identifier-resolution disclosure (#44 B6/B5) — shown exactly when it is
 * load-bearing: the input carries no publisher origin of its own, so SOMETHING has to
 * decide where to look it up. That decision used to be invisible (whichever publisher
 * was listed first in the directory); this names it, and offers the roster as
 * alternatives.
 *
 * TWO inputs are origin-less, and the second is the non-obvious one:
 *   - `bare`         — a hash or slug. Visibly carries no origin.
 *   - `package-blob` — a package-blob URL. LOOKS like it carries an origin, but that
 *                      origin is object storage, not a publisher (B5). Detached
 *                      storage is the common pattern, so the appearance is misleading
 *                      precisely when the user most needs to know which host answered.
 *
 * Deliberately not host-management UI: one sentence and a row of publisher names. No
 * free-text origin entry (a full URL already goes in the main box, host and all), no
 * persistence, no per-host settings. Picking a host re-resolves the SAME identifier
 * there and the share link updates to the two-segment form.
 *
 * The roster lists publishers by TRUST-REGISTRY origin, and this offers those origins
 * as resolution hosts — an inference that holds while a publisher serves its registry
 * and its commitment endpoints on one origin (true for every listed publisher today).
 * The directory schema has no separate resolution-origin field per publisher; see the
 * phase report for why that stayed out of scope here.
 */
function IdentifierResolutionNote({
  kind,
  host,
  onPick,
  disabled,
}: {
  kind: IdentifierResolution;
  host: string;
  onPick: (origin: string) => void;
  disabled: boolean;
}) {
  const isAnchor = host === DEFAULT_HOST;
  // Every listed publisher except the one in use, plus a way back to the anchor when
  // it is not itself listed. De-duplicated by origin.
  const alternatives: { origin: string; label: string }[] = [];
  const seen = new Set<string>([host]);
  for (const p of HOST_DIRECTORY.publishers) {
    if (seen.has(p.registryOrigin)) continue;
    seen.add(p.registryOrigin);
    alternatives.push({ origin: p.registryOrigin, label: p.displayName });
  }
  if (!seen.has(DEFAULT_HOST)) {
    alternatives.unshift({ origin: DEFAULT_HOST, label: hostOf(DEFAULT_HOST) });
  }

  return (
    <p className="mt-3 border-t border-border pt-3 text-xs leading-relaxed text-muted">
      {kind === "bare"
        ? "A hash or slug carries no origin, so it is resolved against "
        : "That URL points at stored package bytes, which name a storage location rather than a publisher — so the package hash in its filename is resolved against "}
      <span className="font-mono text-foreground">{hostOf(host)}</span>
      {isAnchor
        ? " — the host the published directory names for identifiers with no origin of their own."
        : " — the host this link named."}{" "}
      {alternatives.length > 0 && (
        <>
          Try another host:{" "}
          {alternatives.map((a, i) => (
            <span key={a.origin}>
              {i > 0 && " · "}
              <button
                type="button"
                disabled={disabled}
                onClick={() => onPick(a.origin)}
                className="underline decoration-dotted hover:text-accent disabled:cursor-not-allowed disabled:opacity-50"
              >
                {a.label}
              </button>
            </span>
          ))}
          .
        </>
      )}
    </p>
  );
}

function ResolutionSteps({ steps }: { steps: ResolveStep[] }) {
  return (
    <ul className="rounded-lg border border-border bg-surface p-3 text-xs">
      {steps.map((s) => {
        // A `skipped` step retrieved NOTHING (content private, or its location
        // couldn't be reached). A green ✓ would imply a successful fetch, so render a
        // neutral marker + muted label instead (#21).
        const skipped = s.state === "skipped";
        return (
          <li key={s.key} className="flex items-center gap-2 py-0.5">
            <span
              style={{ color: skipped ? "var(--trust-normal)" : "var(--trust-verified)" }}
              aria-hidden
            >
              {skipped ? "–" : "✓"}
            </span>
            <span className={skipped ? "font-medium text-muted" : "font-medium"}>{s.label}</span>
            {!skipped && s.kind === "fetched" && s.url && (
              <span className="truncate font-mono text-muted" title={s.url}>
                {hostOf(s.url)}
              </span>
            )}
            {s.kind === "inline" && <span className="text-muted">(offline)</span>}
          </li>
        );
      })}
    </ul>
  );
}

function asOfDate(iso?: string): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : new Date(t).toISOString().slice(0, 10);
}

function KeyTrustRecheckPanel({
  state,
  onRecheck,
  registryHost,
  bundleStatus,
  setAside,
}: {
  state: { phase: "idle" | "loading" | "done" | "error"; data?: KeyTrustRecheck; error?: string };
  onRecheck: () => void;
  /** The host of the declared https: registry URL the re-check fetches. */
  registryHost: string;
  /** The key-trust status the registry carried in the bundle gave. */
  bundleStatus?: string;
  /** verify-core set the bundle's registry aside for a key-derived signer (#97), so
   *  the bundle established no key status. */
  setAside: boolean;
}) {
  // The rows, headline and recognition carry the re-checked reading, so the panel
  // reports what the live registry said and gives no verdict of its own (#93 item 3).
  return (
    <div className="rounded-lg border border-border bg-surface p-3 text-xs leading-relaxed">
      {state.phase !== "done" && !setAside && (
        <p className="text-muted">
          <strong className="text-foreground">Key trust used the registry carried in this bundle.</strong>{" "}
          It was not checked against the publisher&apos;s domain, and a key revoked after the
          snapshot&apos;s date can&apos;t be seen offline. Re-check against the live registry at{" "}
          <span className="font-mono">{registryHost}</span> to close both gaps.
        </p>
      )}
      {state.phase !== "done" && setAside && (
        <p className="text-muted">
          <strong className="text-foreground">The registry carried in this bundle was not used.</strong>{" "}
          A registry that comes with the bundle cannot establish the key status of a signer whose
          identifier is derived from its key, so no key status was established. Re-check against the
          live registry the record declares, at <span className="font-mono">{registryHost}</span>, to
          establish it.
        </p>
      )}
      {state.phase === "idle" && (
        <button
          type="button"
          onClick={onRecheck}
          className="mt-2 rounded-md border border-border px-2.5 py-1 font-medium hover:border-accent hover:text-accent"
        >
          Re-check against the live registry
        </button>
      )}
      {state.phase === "loading" && (
        <p className="mt-2 text-muted" aria-live="polite">
          Re-checking against the live registry…
        </p>
      )}
      {state.phase === "error" && (
        <p className="mt-2" style={{ color: "var(--trust-attention)" }}>
          The re-check could not run, so nothing on this page changed. {state.error}
        </p>
      )}
      {state.phase === "done" && state.data && (
        <p className="text-muted" aria-live="polite">
          <strong className="text-foreground">Re-checked against the live registry</strong>{" "}
          at <span className="font-mono">{registryHost}</span>
          {state.data.generatedAt ? ` (as of ${asOfDate(state.data.generatedAt)})` : ""}: key trust is{" "}
          <strong>{state.data.status}</strong>
          {setAside ? (
            <>; the registry carried in the bundle was not used</>
          ) : state.data.changed ? (
            <>
              ; the registry carried in the bundle said <strong>{bundleStatus ?? "—"}</strong>
            </>
          ) : (
            <>, the same as the registry carried in the bundle</>
          )}
          . The checks, headline and recognition above now read the live registry.
        </p>
      )}
    </div>
  );
}

function IndependenceNote({ note }: { note: IndependenceNoteData }) {
  return (
    <p className="text-xs leading-relaxed text-muted">
      <strong className="text-foreground">{note.lead}</strong>{" "}
      {note.parts.map((part, i) =>
        part.mono ? (
          <span key={i} className="font-mono">
            {part.text}
          </span>
        ) : (
          <span key={i}>{part.text}</span>
        ),
      )}
    </p>
  );
}

/** A glanceable label for the share path: a truncated `/verify/<id>` or
 *  `/verify/<host>/<id>` for the clean short link — which every publisher now gets —
 *  or a collapsed `/verify?url=…` for the shapes a path segment cannot carry. The
 *  full path lives in the `title` tooltip and is what the Copy button copies. */
function shareLabel(path: string): string {
  if (path.startsWith("/verify?url=")) return "/verify?url=…";
  const segments = path.slice("/verify/".length).split("/");
  const id = segments[segments.length - 1];
  const short = id.length > 12 ? `${id.slice(0, 12)}…` : id;
  return segments.length > 1 ? `/verify/${segments[0]}/${short}` : `/verify/${short}`;
}

function ShareLink({
  path,
  copied,
  onCopy,
}: {
  path: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4 text-xs">
      <span className="text-muted">Shareable result:</span>
      <code className="font-mono" title={path}>
        {shareLabel(path)}
      </code>
      <button
        type="button"
        onClick={onCopy}
        className="rounded-md border border-border px-2.5 py-1 font-medium hover:border-accent hover:text-accent"
      >
        {copied ? "Copied" : "Copy link"}
      </button>
    </div>
  );
}

function hostOf(url?: string): string {
  if (!url) return "";
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}
