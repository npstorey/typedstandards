// Portable verification orchestrator (spec §9.2) — browser-safe.
//
// `verifyEvidence` runs the §9.2 check suite over an already-resolved package +
// its proofs, returning one structured verdict. It is the SINGLE orchestration
// both consumers run: the civicaitools.org server route (which injects its
// `fetch`, its loaded trust registry, and — to preserve its current output — its
// server-deeper lifecycle resolution from the signed attestation chain), and the
// future typedstandards.org browser client (WS3), which injects `window.fetch`
// and resolves the registry + lifecycle STATE from the WS1 commitment sidecar.
// One implementation ⇒ a tampered package fails identically in both; the parity
// test pins this.
//
// `VerifyInput` is shaped to align field-for-field with the WS1 commitment
// sidecar (`buildCommitmentView`) so WS3 can wire sidecar → verifyEvidence with
// no glue. The server route adapts its DB row to the same shape.
//
// Check depth: fully client-side for #1/#2/#3/#4/#5/#6/#9/#12/#13/#14/#15; PRESENCE
// for #7 (RFC 3161); #8 (Rekor) is hash-PARITY AND, when an inclusion proof is
// available (carried for offline, or on the fetched entry), cryptographic Merkle
// inclusion against the pinned log key (civic-ai-tools-website#119 P1); lifecycle
// STATE for #10 unless the caller supplies a deeper resolution. The remaining
// deeper offline crypto (TSA chain #7, independent lifecycle-chain #10) is #119
// P2 / P3.

import { recomputePackageHash } from './checks.ts';
import { verifySignature } from './signature.ts';
import { verifyRekorEntry, type RekorVerifyResult } from './rekor.ts';
import {
  verifyRekorInclusion,
  type RekorInclusionProof,
  type RekorInclusionResult,
} from './rekor-inclusion.ts';
import {
  verifyKeyTrust,
  legacyEmbeddedKeyTrust,
  type KeyTrustResult,
  type TrustRegistry,
} from './trust-registry.ts';
import {
  resolveContentCanonicalization,
  verifyContentHash,
  resolvePackageType,
  checkSignerIdentity,
  checkCaptureMethodVocab,
  verifyPackageBlobRefs,
  type ContentCanonicalizationResolution,
  type ContentHashCheck,
  type TypeResolution,
  type SignerIdentityCheck,
  type CaptureMethodVocabCheck,
  type BlobRefVerification,
} from './checks.ts';
import {
  resolveLifecycleFromLegacyColumns,
  type LifecycleResolution,
} from './lifecycle.ts';
import type { FetchLike } from './types.ts';

/** The parsed signature envelope (`buildCommitmentView`'s `signature`). */
export interface VerifySignatureEnvelope {
  signature: string;
  publicKey: string;
  algorithm?: string;
  kid?: string;
}

/** Lifecycle STATE as carried by the WS1 sidecar (`CommitmentLifecycle`). */
export interface CommitmentLifecycleState {
  status: 'active' | 'withdrawn';
  withdrawnAt?: string;
  withdrawnReason?: string;
  reinstatedAt?: string;
  reinstatedReason?: string;
}

/**
 * Everything `verifyEvidence` needs, aligned to the WS1 commitment sidecar +
 * the package JSON the sidecar's `packageUrl` resolves to.
 */
export interface VerifyInput {
  /** The canonical package JSON (the signed envelope). Null mirrors the server's
   *  "blob unavailable" path: integrity fails and the package-derived checks
   *  report null. */
  package: Record<string, unknown> | null;
  /** The claimed envelope hash (`sidecar.packageHash` / `basePackageHash`). */
  packageHash: string;
  /** The parsed signature envelope (`sidecar.signature`). */
  signature?: VerifySignatureEnvelope | null;
  /** Set by the server route when a present signature COLUMN failed to parse
   *  (a corrupt row): the signature is "present but invalid" → `signatureValid`
   *  is `false` (not `null`) and `hasSigning` is `true`, matching the route's
   *  long-standing try/catch behavior. Normal callers (and the WS3 sidecar,
   *  which carries an already-parsed object) never set this. */
  signatureMalformed?: boolean;
  /** RFC 3161 token (presence only — #7). */
  rfc3161Timestamp?: string | null;
  /** Rekor entry id (#8 hash-parity, needs a fetcher). */
  rekorEntryId?: string | null;
  /** Carried Rekor inclusion proof (#8 deep, civic-ai-tools-website#119). When
   *  supplied with `rekorEntryBody`, Merkle inclusion is verified OFFLINE against
   *  the pinned log key — no fetch, no civicaitools.org dependency. */
  rekorInclusionProof?: RekorInclusionProof | null;
  /** The Rekor entry's canonical leaf bytes (its base64 `body`), carried so the
   *  inclusion proof can be folded offline (D2). */
  rekorEntryBody?: string | null;
  /** Lifecycle STATE from the sidecar (#10 state-depth). Ignored when the caller
   *  supplies `deps.lifecycleResolution`. */
  lifecycle?: CommitmentLifecycleState | null;
  /** Legacy external SHA-256 for the pre-v0.1 content-hash relabel. Defaults to
   *  `packageHash` (they coincide for pre-v0.1 packages). */
  legacyExternalHash?: string;
}

export interface VerifyDeps {
  /** Parsed trust registry (server: loaded; browser: fetched from the sidecar's
   *  `trustRegistryUrl`). */
  registry: TrustRegistry | undefined;
  /** Injected fetcher for #8 / #9. Defaults to `globalThis.fetch`. */
  fetch?: FetchLike;
  /** Optional server-deeper lifecycle resolution (the signed attestation chain).
   *  When provided it is surfaced verbatim, preserving the server route's current
   *  #10 output; when omitted, #10 is derived at STATE depth from
   *  `input.lifecycle`. */
  lifecycleResolution?: LifecycleResolution;
}

/** The structured verdict. Fields mirror the server route's response so the route
 *  can surface them directly. */
export interface VerifyResult {
  hashMatch: boolean;
  recomputedHash: string | null;
  /** = recomputedHash (check #13 nodeId). */
  nodeId: string | null;
  signatureValid: boolean | null;
  /** The signing kid, when the signature carries one. */
  kid?: string;
  hasSigning: boolean;
  rekorVerified: boolean | null;
  rekorDetails: { logIndex?: number; logEntryUrl?: string } | null;
  rekorIntegratedTime?: number;
  /** Cryptographic Merkle-inclusion verdict (#119): null when no proof was
   *  available, else the graded result (`inclusionVerified` / `checkpointVerified`).
   *  Additive to `rekorVerified` (hash-parity). */
  rekorInclusion: RekorInclusionResult | null;
  hasRekor: boolean;
  hasTimestamp: boolean;
  keyTrust: KeyTrustResult | null;
  blobRefsVerified: boolean | null;
  blobRefs: BlobRefVerification[];
  contentCanonicalization: ContentCanonicalizationResolution | null;
  contentHash: ContentHashCheck | null;
  typeResolution: TypeResolution | null;
  signerIdentity: SignerIdentityCheck | null;
  captureMethodVocab: CaptureMethodVocabCheck | null;
  lifecycle: LifecycleResolution;
}

/**
 * Run the §9.2 check suite. The step order mirrors the server route exactly
 * (notably: Rekor before key-trust, because a deprecated-key trust decision is
 * time-bounded by the Rekor `integratedTime`).
 */
export async function verifyEvidence(
  input: VerifyInput,
  deps: VerifyDeps,
): Promise<VerifyResult> {
  const { package: pkg, packageHash } = input;

  // Step 1 — recompute the envelope hash (checks #1 + #13).
  let hashMatch = false;
  let recomputedHash: string | null = null;
  if (pkg) {
    recomputedHash = recomputePackageHash(pkg);
    hashMatch = recomputedHash === packageHash;
  }

  // Step 2 — signature (check #2), dispatching on the stored algorithm (#111).
  let signatureValid: boolean | null = null;
  let sigPublicKey: string | undefined;
  let sigKid: string | undefined;
  if (input.signatureMalformed) {
    // Present-but-corrupt signature column → invalid (no key handles). Gated on
    // `packageHash` to mirror the route's original parse-inside-hash-check block.
    if (packageHash) signatureValid = false;
  } else if (input.signature && packageHash) {
    sigPublicKey = input.signature.publicKey;
    sigKid = input.signature.kid;
    signatureValid = verifySignature(
      packageHash,
      input.signature.signature,
      input.signature.publicKey,
      input.signature.algorithm,
    );
  }
  const hasSigning = !!input.signature || !!input.signatureMalformed;

  // Step 3 — Rekor (check #8). Hash-parity (online) yields integratedTime for #5;
  // Merkle inclusion (#119) is verified cryptographically. The carried proof + body
  // verify inclusion OFFLINE (no fetch); otherwise the online fetch's entry carries
  // the proof. Carried-offline takes precedence — it is the zero-dependency property.
  let rekorVerified: boolean | null = null;
  let rekorDetails: { logIndex?: number; logEntryUrl?: string } | null = null;
  let rekorIntegratedTime: number | undefined;
  let rekorInclusion: RekorInclusionResult | null = null;
  if (input.rekorEntryId && packageHash) {
    const rekorResult: RekorVerifyResult = await verifyRekorEntry(
      input.rekorEntryId,
      packageHash,
      { fetch: deps.fetch },
    );
    rekorVerified = rekorResult.verified;
    rekorIntegratedTime = rekorResult.integratedTime;
    if (rekorResult.logIndex !== undefined) {
      rekorDetails = {
        logIndex: rekorResult.logIndex,
        logEntryUrl: rekorResult.logEntryUrl,
      };
    }
    if (rekorResult.inclusion) rekorInclusion = rekorResult.inclusion;
  }
  if (input.rekorInclusionProof && input.rekorEntryBody) {
    rekorInclusion = verifyRekorInclusion(input.rekorEntryBody, input.rekorInclusionProof);
  }

  // Step 3b — blob references embedded in the package (check #9).
  let blobRefs: BlobRefVerification[] = [];
  let blobRefsVerified: boolean | null = null;
  if (pkg) {
    blobRefs = await verifyPackageBlobRefs(pkg, { fetch: deps.fetch });
    if (blobRefs.length > 0) {
      blobRefsVerified = blobRefs.every((r) => r.ok);
    }
  }

  // Step 4 — key trust against the registry (check #5).
  let keyTrust: KeyTrustResult | null = null;
  if (sigPublicKey && sigKid) {
    keyTrust = verifyKeyTrust(sigPublicKey, sigKid, rekorIntegratedTime, deps.registry);
  } else if (sigPublicKey) {
    keyTrust = legacyEmbeddedKeyTrust();
  }

  // Step 5 — canonicalization, content-hash, and envelope checks (#3/#4/#12/#14/#15).
  let contentCanonicalization: ContentCanonicalizationResolution | null = null;
  let contentHashCheck: ContentHashCheck | null = null;
  let typeResolution: TypeResolution | null = null;
  let signerIdentity: SignerIdentityCheck | null = null;
  let captureMethodVocab: CaptureMethodVocabCheck | null = null;
  if (pkg) {
    contentCanonicalization = resolveContentCanonicalization(pkg);
    contentHashCheck = verifyContentHash(
      pkg,
      contentCanonicalization,
      input.legacyExternalHash ?? packageHash,
    );
    typeResolution = resolvePackageType(pkg);
    signerIdentity = checkSignerIdentity(pkg, sigKid, deps.registry);
    captureMethodVocab = checkCaptureMethodVocab(pkg);
  }

  // Step 6 — lifecycle (check #10). Server-deeper resolution wins when supplied;
  // otherwise derive STATE from the sidecar's lifecycle (the portable depth).
  const lifecycle =
    deps.lifecycleResolution ??
    resolveLifecycleFromLegacyColumns({
      withdrawnAt: input.lifecycle?.withdrawnAt ?? null,
      withdrawnReason: input.lifecycle?.withdrawnReason ?? null,
      reinstatedAt: input.lifecycle?.reinstatedAt ?? null,
      reinstatedReason: input.lifecycle?.reinstatedReason ?? null,
    });

  return {
    hashMatch,
    recomputedHash,
    nodeId: recomputedHash,
    signatureValid,
    ...(sigKid ? { kid: sigKid } : {}),
    hasSigning,
    rekorVerified,
    rekorDetails,
    ...(rekorIntegratedTime !== undefined ? { rekorIntegratedTime } : {}),
    rekorInclusion,
    hasRekor: !!input.rekorEntryId,
    hasTimestamp: !!input.rfc3161Timestamp,
    keyTrust,
    blobRefsVerified,
    blobRefs,
    contentCanonicalization,
    contentHash: contentHashCheck,
    typeResolution,
    signerIdentity,
    captureMethodVocab,
    lifecycle,
  };
}
