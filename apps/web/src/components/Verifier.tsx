"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  detectInputMode,
  describeMode,
  resolveInput,
  buildVerifyInput,
  runVerify,
  resolveCarriedLifecycle,
  buildCheckRows,
  rollupVerdict,
  buildPreview,
  deriveShareTarget,
  resolveHostRecognition,
  registryMetaOf,
  canRecheckKeyTrust,
  recheckKeyTrustLive,
  VerifyFlowError,
  type CheckRow as CheckRowData,
  type HostRecognition,
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
  autoStart = false,
}: {
  initialInput?: string;
  autoStart?: boolean;
}) {
  const [raw, setRaw] = useState(initialInput);
  const [phase, setPhase] = useState<Phase>("idle");
  const [steps, setSteps] = useState<ResolveStep[]>([]);
  const [rows, setRows] = useState<CheckRowData[]>([]);
  const [revealCount, setRevealCount] = useState(0);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [recognition, setRecognition] = useState<HostRecognition | null>(null);
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

  const run = useCallback(async (input: string) => {
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
    setPreview(null);
    setResolved(null);
    setResult(null);
    setRecheck({ phase: "idle" });
    setSharePath(null);
    setCopied(false);

    const mode = detectInputMode(s);
    try {
      const resolvedInput = await resolveInput(mode, s, ac.signal, (step) =>
        setSteps((prev) => [...prev, step]),
      );
      if (ac.signal.aborted) return;
      setResolved(resolvedInput);

      setPhase("verifying");
      // Offline-first for a fully self-contained bundle (#119 Q15): drop the redundant
      // online Rekor parity so verification touches zero network when nothing needs
      // fetching. Hosted/URL verification (fullyOffline=false) is unaffected.
      const vinput = buildVerifyInput(resolvedInput.commitment, resolvedInput.pkg, {
        offline: resolvedInput.fullyOffline,
      });
      // Independently resolve #10 from the carried signed attestation chain (#119 P3);
      // undefined ⇒ verifyEvidence resolves lifecycle at STATE depth.
      const lifecycleResolution = resolveCarriedLifecycle(resolvedInput.commitment);
      const result = await runVerify(vinput, resolvedInput.registry, lifecycleResolution);
      if (ac.signal.aborted) return;
      setResult(result);

      const builtRows = buildCheckRows(
        result,
        vinput,
        resolvedInput.commitment,
        registryMetaOf(resolvedInput),
      );
      setRows(builtRows);
      setVerdict(rollupVerdict(result));
      // The second, independent dimension (Phase D): host recognition. Resolved
      // from the declared registry origin + the directory + the SAME key-trust
      // result, kept orthogonal to the cryptographic verdict above.
      setRecognition(
        resolveHostRecognition(resolvedInput.commitment, result.keyTrust, resolvedInput.directory),
      );
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
    const id = setTimeout(() => void run(initialInput), 0);
    return () => clearTimeout(id);
    // run is stable; only fire for the initial deep-link.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onFile = async (file: File) => {
    const text = await file.text();
    setRaw(text);
    void run(text);
  };

  // Online recheck (#119 P4): re-run the registry-dependent #5 check against the
  // LIVE registry, closing the offline-revocation gap a carried snapshot leaves.
  const onRecheck = useCallback(async () => {
    if (!resolved || !result) return;
    setRecheck({ phase: "loading" });
    try {
      const data = await recheckKeyTrustLive(resolved.commitment, result);
      setRecheck({ phase: "done", data });
    } catch (e) {
      setRecheck({ phase: "error", error: e instanceof Error ? e.message : String(e) });
    }
  }, [resolved, result]);

  const running = phase === "resolving" || phase === "verifying" || phase === "revealing";
  const mode: InputMode = detectInputMode(raw);

  return (
    <div>
      {/* Input */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run(raw);
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
              void run(raw);
            }
          }}
          rows={raw.includes("\n") ? 6 : 1}
          spellCheck={false}
          placeholder="Paste a 64-char package hash, an evidence slug, a hosted URL, or a bundle JSON…"
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
                  <KeyTrustRecheckPanel state={recheck} onRecheck={onRecheck} />
                )}

              {phase === "done" && resolved && <IndependenceNote resolved={resolved} />}

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
}: {
  state: { phase: "idle" | "loading" | "done" | "error"; data?: KeyTrustRecheck; error?: string };
  onRecheck: () => void;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface p-3 text-xs leading-relaxed">
      <p className="text-muted">
        <strong className="text-foreground">Key trust used a registry snapshot.</strong> A
        key revoked after the snapshot&apos;s date can&apos;t be seen offline. Re-check against
        the live registry to close that gap.
      </p>
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
          Couldn&apos;t reach the live registry — you may be offline. {state.error}
        </p>
      )}
      {state.phase === "done" && state.data && (
        <p
          className="mt-2"
          style={{ color: state.data.changed ? "var(--trust-alarm)" : "var(--trust-verified)" }}
          aria-live="polite"
        >
          {state.data.changed ? "⚠ " : "✓ "}
          Live registry
          {state.data.generatedAt ? ` (as of ${asOfDate(state.data.generatedAt)})` : ""}:{" "}
          {state.data.changed ? (
            <>
              key trust is now <strong>{state.data.status}</strong> — this changed after the
              snapshot you verified against.
            </>
          ) : (
            <>
              key trust unchanged (still <strong>{state.data.status}</strong>).
            </>
          )}
        </p>
      )}
    </div>
  );
}

function IndependenceNote({ resolved }: { resolved: ResolvedInput }) {
  const hasDirectory = resolved.directory !== "unavailable";
  if (resolved.fullyOffline) {
    return (
      <p className="text-xs leading-relaxed text-muted">
        <strong className="text-foreground">Fully offline.</strong> Every proof was
        read from your bundle and verified in your browser — nothing was fetched.{" "}
        {hasDirectory
          ? "Publisher recognition used the host-directory snapshot bundled with it."
          : "Your bundle carried no host-directory snapshot, so publisher recognition was skipped."}
      </p>
    );
  }
  const host =
    hostOf(resolved.sources.pkg.url) ||
    hostOf(resolved.sources.commitment.url) ||
    "the publisher";
  return (
    <p className="text-xs leading-relaxed text-muted">
      <strong className="text-foreground">Verified in your browser.</strong> The
      checks ran client-side here — but the package and proofs were fetched from{" "}
      <span className="font-mono">{host}</span>. Publisher recognition was a
      separate lookup in typedstandards.org&apos;s curated host directory,
      independent of that host. To verify with zero trust in the host, download and
      verify an offline bundle.
    </p>
  );
}

/** A glanceable label for the share path: a truncated `/verify/<id>` for the clean
 *  short link, or a collapsed `/verify?url=…` for the cross-host fallback. The full
 *  path lives in the `title` tooltip and is what the Copy button actually copies. */
function shareLabel(path: string): string {
  if (path.startsWith("/verify?url=")) return "/verify?url=…";
  const id = path.slice("/verify/".length);
  return `/verify/${id.length > 12 ? `${id.slice(0, 12)}…` : id}`;
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
