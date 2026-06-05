"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  detectInputMode,
  describeMode,
  resolveInput,
  buildVerifyInput,
  runVerify,
  buildCheckRows,
  rollupVerdict,
  buildPreview,
  VerifyFlowError,
  type CheckRow as CheckRowData,
  type InputMode,
  type PagePreview as PreviewData,
  type ResolveStep,
  type ResolvedInput,
  type Verdict,
} from "@/lib/verify-flow";
import { CheckRow } from "./CheckRow";
import { VerdictBanner } from "./VerdictBanner";
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
  const [preview, setPreview] = useState<PreviewData | null>(null);
  const [resolved, setResolved] = useState<ResolvedInput | null>(null);
  const [shareHash, setShareHash] = useState<string | null>(null);
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
    setPreview(null);
    setResolved(null);
    setShareHash(null);
    setCopied(false);

    const mode = detectInputMode(s);
    try {
      const resolvedInput = await resolveInput(mode, s, ac.signal, (step) =>
        setSteps((prev) => [...prev, step]),
      );
      if (ac.signal.aborted) return;
      setResolved(resolvedInput);

      setPhase("verifying");
      const vinput = buildVerifyInput(resolvedInput.commitment, resolvedInput.pkg);
      const result = await runVerify(vinput, resolvedInput.registry);
      if (ac.signal.aborted) return;

      const builtRows = buildCheckRows(result, vinput, resolvedInput.commitment);
      setRows(builtRows);
      setVerdict(rollupVerdict(result));
      setPreview(buildPreview(resolvedInput.pkg, resolvedInput.commitment));

      setPhase("revealing");
      for (let i = 1; i <= builtRows.length; i++) {
        if (ac.signal.aborted) return;
        setRevealCount(i);
        await delay(160);
      }
      if (ac.signal.aborted) return;
      setPhase("done");

      // Shareable result URL (hash/url modes resolve the same way from the hash).
      if (mode !== "bundle" && resolvedInput.commitment.packageHash) {
        const hash = resolvedInput.commitment.packageHash;
        setShareHash(hash);
        if (typeof window !== "undefined") {
          window.history.replaceState(null, "", `/verify/${hash}`);
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
              {phase === "done" && verdict && <VerdictBanner verdict={verdict} />}

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

              {phase === "done" && resolved && <IndependenceNote resolved={resolved} />}

              {phase === "done" && preview && <PagePreview preview={preview} />}

              {phase === "done" && shareHash && (
                <ShareLink hash={shareHash} copied={copied} onCopy={() => {
                  const url = `${window.location.origin}/verify/${shareHash}`;
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
      {steps.map((s) => (
        <li key={s.key} className="flex items-center gap-2 py-0.5">
          <span style={{ color: "var(--trust-verified)" }} aria-hidden>
            ✓
          </span>
          <span className="font-medium">{s.label}</span>
          {s.kind === "fetched" && s.url && (
            <span className="truncate font-mono text-muted" title={s.url}>
              {hostOf(s.url)}
            </span>
          )}
          {s.kind === "inline" && <span className="text-muted">(offline)</span>}
        </li>
      ))}
    </ul>
  );
}

function IndependenceNote({ resolved }: { resolved: ResolvedInput }) {
  if (resolved.fullyOffline) {
    return (
      <p className="text-xs leading-relaxed text-muted">
        <strong className="text-foreground">Fully offline.</strong> Every proof was
        read from your bundle and verified in your browser — nothing was fetched.
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
      <span className="font-mono">{host}</span>. To verify with zero trust in the
      host, download and verify an offline bundle.
    </p>
  );
}

function ShareLink({
  hash,
  copied,
  onCopy,
}: {
  hash: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4 text-xs">
      <span className="text-muted">Shareable result:</span>
      <code className="font-mono">/verify/{hash.slice(0, 12)}…</code>
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
