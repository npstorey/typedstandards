// Verification flow for the typedstandards.org client-side verifier (#116 WS3
// Phase C). Pure helpers the <Verifier> client component sequences:
//
//   detect input  →  resolve the WS1 commitment  →  fetch package + registry
//   →  verifyEvidence (the SAME @typedstandards/verify-core both sites run)
//   →  build the per-check "show the math" rows + the rolled-up verdict.
//
// All network I/O is a plain GET with no custom request headers, so the fetch
// follows civicaitools.org's site-wide 307 to its canonical host transparently
// (a custom header would trigger a CORS preflight whose OPTIONS hits the 307 and
// can be rejected). Verification depth MATCHES verify-core / the civicaitools.org
// server: full client-side crypto for #1–#6/#9/#12–#15, PRESENCE for #7 (RFC
// 3161), hash-PARITY for #8 (Rekor), STATE for #10 (lifecycle). The deeper offline
// crypto (TSA chain, Merkle inclusion, signed lifecycle chain) is #119, not here.

import {
  verifyEvidence,
  validateRegistry,
  type VerifyInput,
  type VerifyResult,
  type VerifySignatureEnvelope,
  type CommitmentLifecycleState,
  type TrustRegistry,
} from '@typedstandards/verify-core';
import {
  type TrustTier,
  type ResolvedTrustSignal,
  type TrustSignalDescriptor,
  toResolvedSignal,
  resolveEnvelopeIntegrity,
  resolveSignature,
  resolveKeyTrust,
  resolveTimestamp,
  resolveRekor,
  resolveBlobRefs,
  resolveCaptureMethodLabel,
  CONTENT_CANONICALIZATION_SIGNALS,
  CONTENT_HASH_SIGNALS,
  TYPE_RESOLUTION_SIGNALS,
  SIGNER_IDENTITY_SIGNALS,
  CAPTURE_METHOD_VOCAB_SIGNALS,
  LIFECYCLE_STATE_SIGNALS,
  LIFECYCLE_SOURCE_SIGNALS,
} from './trust-signal';
import {
  PRIMARY_HOST,
  HOST_DIRECTORY_PATH,
  fetchHostDirectory,
  validateHostDirectory,
  type HostDirectory,
} from './host-directory';

// Re-export the host-recognition surface (Phase D / Q47) so the verifier UI pulls
// the whole verification flow — cryptographic checks AND publisher recognition —
// from this one module.
export { resolveHostRecognition } from './host-directory';
export type {
  HostDirectory,
  HostDirectoryEntry,
  HostRecognition,
  HostRecognitionStatus,
} from './host-directory';

/** The host a bare hash / slug is resolved against — there is no origin in a bare
 *  identifier, so it is looked up on the directory's anchor host. Derived from the
 *  published host directory (Phase D / Q47) rather than a standalone hardcoded
 *  constant, so the directory is the single source of truth for which hosts the
 *  verifier knows about. Recognition itself is directory-driven (see
 *  resolveHostRecognition), never keyed off this constant. */
export const DEFAULT_HOST = PRIMARY_HOST;

/** The §9.2.1 commitment sidecar shape (what the WS1 endpoint returns). A bundle
 *  may additionally carry `package` / `trustRegistry` inline for offline use. */
export interface Commitment {
  evidenceProtocolVersion?: string;
  packageHash: string;
  packageUrl?: string;
  captureMethod?: string | null;
  contentProfile?: string;
  producerProfile?: string;
  type?: string;
  signer?: { bindingTier?: string; identifier?: string; displayName?: string };
  contentHash?: Record<string, string>;
  contentCanonicalization?: string;
  signature?: VerifySignatureEnvelope | null;
  signerIdentity?: {
    provider?: string;
    providerId?: string;
    displayName?: string;
    profileUrl?: string;
  } | null;
  rfc3161Timestamp?: string | null;
  rekorEntryId?: string | null;
  rekorInclusionProof?: string | null;
  lifecycle?: CommitmentLifecycleState | null;
  trustRegistryUrl?: string;
  trustRegistryUrlLegacy?: string;
  subjectTitle?: string;
  subjectSummary?: string;
  /** Offline bundle extensions (not emitted by the endpoint). */
  package?: Record<string, unknown> | null;
  trustRegistry?: unknown;
  /** Offline snapshot of the typedstandards.org host directory, so a bundle can
   *  resolve publisher recognition without a network fetch (same staleness caveat
   *  as the registry snapshot — Q47 / #119). */
  hostDirectory?: unknown;
}

export type InputMode = 'hash' | 'url' | 'bundle';

export class VerifyFlowError extends Error {}

// --- Input detection ------------------------------------------------------

const HASH_RE = /^[0-9a-f]{64}$/i;

/**
 * Auto-detect the input kind. A 64-hex string is a package hash; an http(s) URL
 * is a hosted reference; a string starting with `{` is a pasted bundle/commitment
 * JSON; anything else is treated as an evidence slug (resolved like a hash).
 */
export function detectInputMode(raw: string): InputMode {
  const s = raw.trim();
  if (!s) return 'hash';
  if (s.startsWith('{')) return 'bundle';
  if (/^https?:\/\//i.test(s)) return 'url';
  return 'hash'; // 64-hex hash OR an evidence slug — both resolve by identifier
}

/** A glanceable label for the detected mode. */
export function describeMode(mode: InputMode, raw: string): string {
  if (mode === 'bundle') return 'Uploaded bundle';
  if (mode === 'url') return 'Hosted URL';
  return HASH_RE.test(raw.trim()) ? 'Package hash' : 'Evidence slug';
}

// --- Resolution -----------------------------------------------------------

/** How a piece of the verification input was obtained — drives the honest
 *  per-mode independence guarantee shown in the UI. */
export type SourceKind = 'fetched' | 'inline';

export interface ResolvedInput {
  commitment: Commitment;
  pkg: Record<string, unknown> | null;
  registry: TrustRegistry | undefined;
  /** The host directory used for publisher recognition (Phase D), or
   *  `'unavailable'` when it could not be loaded. Distinct from the publisher
   *  sources below: it comes from the verifier's curator (typedstandards.org),
   *  not from the package's host, so it is tracked separately. */
  directory: HostDirectory | 'unavailable';
  /** Where each piece came from, for the independence disclosure. */
  sources: {
    commitment: { kind: SourceKind; url?: string };
    pkg: { kind: SourceKind; url?: string };
    registry: { kind: SourceKind; url?: string };
  };
  /** True only when EVERYTHING was read from the bundle — i.e. a true offline
   *  verification, fetching nothing. */
  fullyOffline: boolean;
}

async function getJson(url: string, signal?: AbortSignal): Promise<unknown> {
  let res: Awaited<ReturnType<typeof fetch>>;
  try {
    // Plain GET, no custom headers (see the module header re: the 307 / preflight).
    res = await fetch(url, { signal });
  } catch (err) {
    throw new VerifyFlowError(
      `Could not reach ${shortUrl(url)} — the host may be unreachable or block cross-origin reads. (${
        err instanceof Error ? err.message : 'network error'
      })`,
    );
  }
  if (!res.ok) {
    if (res.status === 404) {
      throw new VerifyFlowError(
        `Nothing found at ${shortUrl(url)} (404). For a hash, paste the full 64-character hash or the package's slug.`,
      );
    }
    throw new VerifyFlowError(`Request to ${shortUrl(url)} failed (HTTP ${res.status}).`);
  }
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('json')) {
    throw new VerifyFlowError(
      `${shortUrl(url)} did not return JSON (content-type "${ct || 'unknown'}") — it may be an auth wall or a wrong URL.`,
    );
  }
  return res.json();
}

/** Build the commitment-endpoint URL for a hosted URL input. Handles a direct
 *  commitment URL, an evidence detail/api URL, and a package-blob URL (the badge
 *  deep-link passes `?url=<package-url>`, whose filename is the hash). */
export function deriveCommitmentUrl(input: string): string {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new VerifyFlowError(`"${input}" is not a valid URL.`);
  }
  if (u.pathname.endsWith('/commitment')) return u.toString();
  const idMatch = u.pathname.match(/\/evidence\/([^/]+)/);
  if (idMatch) return `${u.origin}/api/evidence/${idMatch[1]}/commitment`;
  const blobHash = u.pathname.match(/([0-9a-f]{64})\.json$/i);
  if (blobHash) return `${DEFAULT_HOST}/api/evidence/${blobHash[1]}/commitment`;
  // Last resort: treat the URL itself as the commitment resource.
  return u.toString();
}

/** Step 1 — resolve the commitment for hash / URL / bundle input. */
export async function resolveCommitment(
  mode: InputMode,
  raw: string,
  signal?: AbortSignal,
): Promise<{ commitment: Commitment; url?: string }> {
  const s = raw.trim();
  if (mode === 'bundle') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(s);
    } catch {
      throw new VerifyFlowError('That bundle is not valid JSON.');
    }
    const commitment = parsed as Commitment;
    if (!commitment || typeof commitment !== 'object' || !commitment.packageHash) {
      throw new VerifyFlowError(
        'That JSON is not a commitment bundle (it has no `packageHash`). Paste the output of an /api/evidence/<id>/commitment endpoint.',
      );
    }
    return { commitment };
  }
  const url =
    mode === 'hash'
      ? `${DEFAULT_HOST}/api/evidence/${encodeURIComponent(s)}/commitment`
      : deriveCommitmentUrl(s);
  const commitment = (await getJson(url, signal)) as Commitment;
  if (!commitment?.packageHash) {
    throw new VerifyFlowError(`${shortUrl(url)} did not return a commitment (no \`packageHash\`).`);
  }
  return { commitment, url };
}

/** A resolution step, emitted as each piece is obtained (drives the live UI). */
export interface ResolveStep {
  key: 'commitment' | 'package' | 'registry' | 'directory';
  label: string;
  kind: SourceKind;
  url?: string;
}

/** Steps 2 + 3 — fetch (or read inline) the package blob and the trust registry.
 *  `onStep` fires as each piece resolves so the UI can show it happening live. */
export async function resolveInput(
  mode: InputMode,
  raw: string,
  signal?: AbortSignal,
  onStep?: (step: ResolveStep) => void,
): Promise<ResolvedInput> {
  const { commitment, url: commitmentUrl } = await resolveCommitment(mode, raw, signal);
  const commitmentKind: SourceKind = mode === 'bundle' ? 'inline' : 'fetched';
  onStep?.({
    key: 'commitment',
    label: commitmentKind === 'inline' ? 'Read commitment from bundle' : 'Fetched commitment sidecar',
    kind: commitmentKind,
    ...(commitmentUrl ? { url: commitmentUrl } : {}),
  });

  // Package blob.
  let pkg: Record<string, unknown> | null;
  let pkgSource: { kind: SourceKind; url?: string };
  if (commitment.package) {
    pkg = commitment.package;
    pkgSource = { kind: 'inline' };
  } else if (commitment.packageUrl) {
    pkg = (await getJson(commitment.packageUrl, signal)) as Record<string, unknown>;
    pkgSource = { kind: 'fetched', url: commitment.packageUrl };
  } else {
    // No blob and no inline package: integrity can't be checked (mirrors the
    // server's "blob unavailable" path — verifyEvidence reports nulls).
    pkg = null;
    pkgSource = { kind: 'fetched' };
  }
  onStep?.({
    key: 'package',
    label: pkgSource.kind === 'inline' ? 'Read package from bundle' : 'Fetched package blob',
    kind: pkgSource.kind,
    ...(pkgSource.url ? { url: pkgSource.url } : {}),
  });

  // Trust registry.
  let registry: TrustRegistry | undefined;
  let registrySource: { kind: SourceKind; url?: string };
  if (commitment.trustRegistry !== undefined) {
    registry = validateRegistry(commitment.trustRegistry);
    registrySource = { kind: 'inline' };
  } else {
    const registryUrl = commitment.trustRegistryUrl ?? commitment.trustRegistryUrlLegacy;
    if (registryUrl) {
      registry = validateRegistry(await getJson(registryUrl, signal));
      registrySource = { kind: 'fetched', url: registryUrl };
    } else {
      registry = undefined;
      registrySource = { kind: 'fetched' };
    }
  }
  onStep?.({
    key: 'registry',
    label: registrySource.kind === 'inline' ? 'Read trust registry from bundle' : 'Fetched publisher trust registry',
    kind: registrySource.kind,
    ...(registrySource.url ? { url: registrySource.url } : {}),
  });

  // Host directory (Phase D recognition dimension). It is the verifier's curator
  // data, not the package's, so it is resolved separately from the publisher
  // sources above. Bundle mode honours the offline intent: an embedded snapshot is
  // used if present, otherwise the network is NOT touched (recognition then reads
  // a calm "directory unavailable"). Online modes fetch the canonical same-origin
  // directory; any failure degrades to 'unavailable' without affecting the
  // cryptographic verdict.
  let directory: HostDirectory | 'unavailable';
  let directoryStep: SourceKind | null = null;
  if (commitment.hostDirectory !== undefined) {
    directory = validateHostDirectory(commitment.hostDirectory) ?? 'unavailable';
    if (directory !== 'unavailable') directoryStep = 'inline';
  } else if (mode === 'bundle') {
    directory = 'unavailable';
  } else {
    directory = await fetchHostDirectory(globalThis.fetch, HOST_DIRECTORY_PATH, signal);
    if (directory !== 'unavailable') directoryStep = 'fetched';
  }
  if (directoryStep) {
    onStep?.({
      key: 'directory',
      label:
        directoryStep === 'inline'
          ? 'Read publisher directory from bundle'
          : 'Loaded the typedstandards.org publisher directory',
      kind: directoryStep,
    });
  }

  const fullyOffline =
    mode === 'bundle' && pkgSource.kind === 'inline' && registrySource.kind === 'inline';

  return {
    commitment,
    pkg,
    registry,
    directory,
    sources: {
      commitment: { kind: mode === 'bundle' ? 'inline' : 'fetched', url: commitmentUrl },
      pkg: pkgSource,
      registry: registrySource,
    },
    fullyOffline,
  };
}

/** Map the resolved commitment + package to the verify-core input. */
export function buildVerifyInput(commitment: Commitment, pkg: Record<string, unknown> | null): VerifyInput {
  return {
    package: pkg,
    packageHash: commitment.packageHash,
    signature: commitment.signature ?? null,
    rfc3161Timestamp: commitment.rfc3161Timestamp ?? null,
    rekorEntryId: commitment.rekorEntryId ?? null,
    lifecycle: commitment.lifecycle ?? null,
  };
}

/** Run the §9.2 check suite in the browser. */
export function runVerify(input: VerifyInput, registry: TrustRegistry | undefined): Promise<VerifyResult> {
  return verifyEvidence(input, { registry, fetch: globalThis.fetch });
}

// --- "Show the math" rows -------------------------------------------------

export interface MathLine {
  label: string;
  value: string;
  /** Render value in monospace (hashes, keys, ids). */
  mono?: boolean;
  /** The full value, when `value` is truncated for display. */
  full?: string;
}

export interface CheckRow {
  num: string;
  name: string;
  signal: ResolvedTrustSignal;
  math: MathLine[];
  /** Honest depth caveat (e.g. presence-only #7, hash-parity #8). */
  depthNote?: string;
}

function truncMiddle(s: string, head = 10, tail = 8): string {
  return s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
}

function row(
  num: string,
  name: string,
  descriptor: TrustSignalDescriptor,
  math: MathLine[],
  depthNote?: string,
): CheckRow {
  return { num, name, signal: toResolvedSignal(descriptor), math, ...(depthNote ? { depthNote } : {}) };
}

/**
 * Build the per-check rows from the verdict + input. Each row carries the trust
 * signal (tier/label) AND the computed values the verifier saw — the "math".
 * Ordered by spec §9.2 check number. Null checks (e.g. on a missing package) are
 * skipped rather than rendered as failures.
 */
export function buildCheckRows(
  result: VerifyResult,
  input: VerifyInput,
  commitment: Commitment,
): CheckRow[] {
  const rows: CheckRow[] = [];

  // #1 — envelope integrity.
  rows.push(
    row('1', 'Envelope integrity', resolveEnvelopeIntegrity(result.hashMatch), [
      {
        label: 'Recomputed SHA-256',
        value: result.recomputedHash ? truncMiddle(result.recomputedHash) : '—',
        mono: true,
        ...(result.recomputedHash ? { full: result.recomputedHash } : {}),
      },
      { label: 'Claimed hash', value: truncMiddle(input.packageHash), mono: true, full: input.packageHash },
    ]),
  );

  // #2 — signature.
  if (result.hasSigning || input.signature) {
    const sig = commitment.signature ?? input.signature ?? undefined;
    rows.push(
      row('2', 'Signature', resolveSignature(result.signatureValid), [
        { label: 'Algorithm', value: sig?.algorithm ?? 'Ed25519ph (default)' },
        {
          label: 'Public key',
          value: sig?.publicKey ? truncMiddle(sig.publicKey, 12, 6) : '—',
          mono: true,
          ...(sig?.publicKey ? { full: sig.publicKey } : {}),
        },
        { label: 'Signs', value: 'the package hash' },
      ]),
    );
  } else {
    rows.push(row('2', 'Signature', resolveSignature(null), [{ label: 'Status', value: 'no signature present' }]));
  }

  // #3 — content canonicalization.
  if (result.contentCanonicalization) {
    rows.push(
      row('3', 'Canonicalization', CONTENT_CANONICALIZATION_SIGNALS[result.contentCanonicalization.status], [
        { label: 'Rule', value: result.contentCanonicalization.rule, mono: true },
      ]),
    );
  }

  // #4 — content hash.
  if (result.contentHash) {
    const ch = result.contentHash;
    const math: MathLine[] = [];
    if (ch.algorithms?.length) math.push({ label: 'Algorithms', value: ch.algorithms.join(', ') });
    if (ch.matched) math.push({ label: 'Matched', value: ch.matched });
    if (ch.contentHash?.sha256)
      math.push({
        label: 'contentHash.sha256',
        value: truncMiddle(ch.contentHash.sha256),
        mono: true,
        full: ch.contentHash.sha256,
      });
    rows.push(row('4', 'Content fingerprint', CONTENT_HASH_SIGNALS[ch.status], math));
  }

  // #5 — key trust (trust-registry lookup).
  if (result.keyTrust) {
    rows.push(
      row('5', 'Key trust', resolveKeyTrust(result.keyTrust), [
        { label: 'kid', value: result.kid ?? '—', mono: true },
        { label: 'Registry status', value: result.keyTrust.status },
      ]),
    );
  } else {
    rows.push(row('5', 'Key trust', resolveKeyTrust(null), [{ label: 'Status', value: 'no signing key to check' }]));
  }

  // #7 — RFC 3161 timestamp (PRESENCE only).
  rows.push(
    row(
      '7',
      'Timestamp',
      resolveTimestamp(result.hasTimestamp),
      [{ label: 'RFC 3161 token', value: result.hasTimestamp ? 'present' : 'absent' }],
      'Presence only — the timestamp token is not cryptographically chain-verified here (#119).',
    ),
  );

  // #8 — Rekor transparency log (hash-PARITY).
  if (result.hasRekor) {
    const math: MathLine[] = [];
    if (result.rekorDetails?.logIndex !== undefined)
      math.push({ label: 'Log index', value: String(result.rekorDetails.logIndex), mono: true });
    if (input.rekorEntryId) math.push({ label: 'Entry', value: truncMiddle(input.rekorEntryId, 12, 6), mono: true, full: input.rekorEntryId });
    rows.push(
      row(
        '8',
        'Transparency log',
        resolveRekor(result.rekorVerified),
        math.length ? math : [{ label: 'Status', value: 'checked' }],
        'Hash-parity — the entry hash is compared; the Merkle inclusion proof is not yet recomputed (#119).',
      ),
    );
  }

  // #9 — blob references.
  if (result.blobRefsVerified !== null) {
    rows.push(
      row('9', 'Referenced content', resolveBlobRefs(result.blobRefsVerified), [
        { label: 'References', value: String(result.blobRefs.length) },
        { label: 'All verified', value: result.blobRefsVerified ? 'yes' : 'no' },
      ]),
    );
  }

  // #10 — lifecycle state.
  {
    const state = LIFECYCLE_STATE_SIGNALS[result.lifecycle.status];
    const source = LIFECYCLE_SOURCE_SIGNALS[result.lifecycle.source];
    rows.push(
      row('10', 'Lifecycle', state, [
        { label: 'State', value: result.lifecycle.status },
        { label: 'Derived from', value: source.label },
      ]),
    );
  }

  // #12 — type resolution.
  if (result.typeResolution) {
    rows.push(
      row('12', 'Node type', TYPE_RESOLUTION_SIGNALS[result.typeResolution.status], [
        { label: 'type', value: result.typeResolution.type, mono: true },
      ]),
    );
  }

  // #14 — signer identity cross-check.
  if (result.signerIdentity) {
    const si = result.signerIdentity;
    const math: MathLine[] = [];
    if (si.claimed) math.push({ label: 'Claimed signer', value: si.claimed, mono: true });
    if (si.registered) math.push({ label: 'Registry identity', value: si.registered, mono: true });
    rows.push(row('14', 'Signer identity', SIGNER_IDENTITY_SIGNALS[si.status], math.length ? math : [{ label: 'Status', value: si.status }]));
  }

  // #15 — captureMethod vocabulary (+ the P1 captureMethod disclosure label).
  if (result.captureMethodVocab) {
    const cm = result.captureMethodVocab;
    const math: MathLine[] = [{ label: 'captureMethod', value: cm.captureMethod ?? '—', mono: true }];
    const label = resolveCaptureMethodLabel(cm.captureMethod ?? commitment.captureMethod ?? null);
    if (label) math.push({ label: 'How it was captured', value: label });
    rows.push(row('15', 'Capture method', CAPTURE_METHOD_VOCAB_SIGNALS[cm.status], math));
  }

  return rows;
}

// --- Verdict roll-up ------------------------------------------------------

export interface Verdict {
  tier: TrustTier;
  headline: string;
  detail: string;
}

/**
 * Roll the per-check verdicts into one headline (P5 glance layer). An alarm on any
 * load-bearing integrity check fails the package; a fully-green signed core
 * verifies; a signed-but-intact package with unconfirmed elements reads as
 * "verified, with caveats"; an unsigned package reads calm.
 */
export function rollupVerdict(result: VerifyResult): Verdict {
  const alarm =
    result.hashMatch === false ||
    result.signatureValid === false ||
    result.contentHash?.status === 'content_hash_mismatch' ||
    result.blobRefsVerified === false ||
    result.signerIdentity?.status === 'signer_identity_mismatch' ||
    result.keyTrust?.status === 'revoked' ||
    result.keyTrust?.status === 'deprecated_invalid';

  if (alarm) {
    return {
      tier: 'alarm',
      headline: 'Verification failed',
      detail:
        'A load-bearing integrity or identity check did not pass — this package may have been altered or is signed by an untrusted key. See the checks below.',
    };
  }

  if (result.signatureValid === null && !result.hasSigning) {
    return {
      tier: 'normal',
      headline: 'Not signed',
      detail: 'This package carries no signature, so there is nothing to verify cryptographically.',
    };
  }

  const fullyGreen =
    result.hashMatch === true &&
    result.signatureValid === true &&
    result.keyTrust?.status === 'active';

  if (fullyGreen) {
    return {
      tier: 'verified',
      headline: 'Verified',
      detail:
        'The bytes are intact, the signature verifies, and the signing key is active in the publisher’s trust registry. This confirms integrity and identity — not whether the content is correct.',
    };
  }

  return {
    tier: 'attention',
    headline: 'Verified, with caveats',
    detail:
      'The core signature and integrity checks pass, but something is unconfirmed or unrecognized (see the amber checks). Not proven bad — just not fully affirmed.',
  };
}

// --- Page preview (from the VERIFIED package bytes) -----------------------

export interface PagePreview {
  /** Whether the package bytes were available to render. */
  available: boolean;
  type?: string;
  signerDisplayName?: string;
  captureMethod?: string;
  summary?: string;
  answer?: string;
  /** The publisher's listing title (from the commitment — NOT signed). */
  listingTitle?: string;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/**
 * Build the page preview from the VERIFIED package JSON, so "what you see" is
 * "what was signed". `summary` and `answer` (the package's `output`) are signed
 * envelope fields. The listing title comes from the commitment (publisher's DB
 * record, NOT signed) and is shown only as context, clearly labeled.
 */
export function buildPreview(
  pkg: Record<string, unknown> | null,
  commitment: Commitment,
): PagePreview {
  if (!pkg) {
    return {
      available: false,
      ...(str(commitment.subjectTitle) ? { listingTitle: commitment.subjectTitle } : {}),
    };
  }
  const signer = pkg['signer'] as { displayName?: string } | undefined;
  const metadata = pkg['metadata'] as { captureMethod?: string } | undefined;
  return {
    available: true,
    ...(str(pkg['type']) ? { type: pkg['type'] as string } : {}),
    ...(str(signer?.displayName) ? { signerDisplayName: signer!.displayName } : {}),
    ...(str(metadata?.captureMethod) ? { captureMethod: metadata!.captureMethod } : {}),
    ...(str(pkg['summary']) ? { summary: pkg['summary'] as string } : {}),
    ...(str(pkg['output']) ? { answer: pkg['output'] as string } : {}),
    ...(str(commitment.subjectTitle) ? { listingTitle: commitment.subjectTitle } : {}),
  };
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.host + u.pathname;
  } catch {
    return url;
  }
}
