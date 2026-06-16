import type { PagePreview as PreviewData } from "@/lib/verify-flow";

/** Render the package from its VERIFIED bytes, so "what you see" is "what was
 *  signed". `summary` and `answer` are signed envelope fields; the listing title
 *  comes from the publisher's record (NOT signed) and is labeled as such. v1 is a
 *  plain-text render — the shared rich body renderer (#115) swaps in later. */
export function PagePreview({ preview }: { preview: PreviewData }) {
  if (!preview.available) {
    return (
      <div className="rounded-lg border border-border bg-surface p-4 text-sm text-muted">
        {preview.unavailableReason === "private"
          ? "This package’s content is private, so there is nothing to preview here. The public commitment’s proofs above were still verified."
          : "The package bytes could not be fetched, so there is nothing to preview. The proofs above were still checked against the commitment."}
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border p-5">
      <p className="font-mono text-xs uppercase tracking-[0.15em] text-muted">
        What was signed
      </p>

      {preview.listingTitle && (
        <h3 className="mt-2 font-display text-lg font-semibold">
          {preview.listingTitle}
          <span className="ml-2 align-middle text-xs font-normal text-muted">
            (publisher’s listing title — not part of the signed bytes)
          </span>
        </h3>
      )}

      <div className="mt-3 flex flex-wrap gap-2 text-xs">
        {preview.type && <Chip label="type" value={preview.type} />}
        {preview.signerDisplayName && <Chip label="signer" value={preview.signerDisplayName} />}
        {preview.captureMethod && <Chip label="captureMethod" value={preview.captureMethod} />}
      </div>

      {preview.summary && (
        <div className="mt-4">
          <p className="text-xs text-muted">Summary</p>
          <p className="mt-1 text-sm leading-relaxed">{preview.summary}</p>
        </div>
      )}

      {preview.answer && (
        <div className="mt-4">
          <p className="text-xs text-muted">Answer</p>
          <pre className="mt-1 max-h-96 overflow-auto whitespace-pre-wrap rounded-md bg-surface p-3 font-sans text-sm leading-relaxed">
            {preview.answer}
          </pre>
        </div>
      )}

      <p className="mt-4 border-t border-border pt-3 text-xs text-muted">
        Rendered from the verified package bytes. This confirms these are the bytes
        the signature covers — not that the content is correct (P1: disclosure ≠
        validation).
      </p>
    </div>
  );
}

function Chip({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-border px-2.5 py-1">
      <span className="text-muted">{label}</span>
      <span className="font-mono">{value}</span>
    </span>
  );
}
