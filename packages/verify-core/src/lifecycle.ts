// Lifecycle attestation checks (spec §9.2 check #10, §8.10) — browser-safe pure
// logic.
//
// Lifecycle state (withdrawn / active) is derived from a chain of separately-
// signed `attestation/*` nodes referencing the content node by `targetNodeId`,
// each verified independently. Backwards-compat (§8.10.4): when no attestation
// envelopes are present, the legacy `withdrawnAt` / `reinstatedAt` columns are
// honored instead.
//
// This file holds only the PURE ordering / status-derivation / per-node
// verification logic (factored from the server `verify.ts`). The DB + blob fetch
// orchestration that assembles the chain stays in the server `lifecycle.ts`,
// which imports these. WS2's portable orchestrator (`verify.ts` →
// `verifyEvidence`) consumes lifecycle at STATE depth (the sidecar's
// status/withdrawnAt/reason) rather than re-running the chain — verifying the
// signed attestation chain independently in the browser is civic-ai-tools-website#119.

import { computeEnvelopeHash } from './canonicalization.ts';
import { verifySignature } from './signature.ts';
import {
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  LIFECYCLE_ATTESTATION_TYPES,
} from './attestation.ts';
import type { SignerIdentity } from './types.ts';

export const LIFECYCLE_STATUSES = ['active', 'withdrawn'] as const;
export type LifecycleStatus = (typeof LIFECYCLE_STATUSES)[number];

/** Which representation determined the lifecycle status. `none` = never
 *  withdrawn, no attestations and no legacy columns. */
export const LIFECYCLE_SOURCES = [
  'attestation-chain',
  'legacy-columns',
  'none',
] as const;
export type LifecycleSource = (typeof LIFECYCLE_SOURCES)[number];

/** A single verified lifecycle attestation, as surfaced in the chain. */
export interface LifecycleAttestationView {
  nodeId: string;
  type: string;
  signer?: SignerIdentity;
  /** Envelope timestamp (the node's `metadata.createdAt`) — the chain sort key. */
  createdAt: string;
  reason?: string;
  effectiveAt?: string;
  priorWithdrawalNodeId?: string;
  /** Ed25519ph signature over the recomputed nodeId; null when unsigned. */
  signatureValid: boolean | null;
  /** Recomputed envelope hash equals the stored nodeId (integrity). */
  nodeIdMatches: boolean;
  /** RFC 3161 timestamp token present (presence surfaced; full TSA-chain
   *  verification is the same out-of-scope item as for content nodes). */
  hasTimestamp: boolean;
  /** Rekor inclusion-proof entry present (presence only; per-attestation Rekor
   *  cryptographic verification is a follow-up). */
  hasRekor: boolean;
  /** Publisher-only conformance (§8.12.3): the attestation's signer.identifier
   *  matches the target content node's signer.identifier. */
  signerMatchesTarget: boolean;
}

export interface LifecycleResolution {
  status: LifecycleStatus;
  /** Which representation determined the status (see `LIFECYCLE_SOURCES`). */
  source: LifecycleSource;
  /** The ordered lifecycle attestation chain (envelope-timestamp asc, ties by
   *  nodeId lexicographic). Empty for the legacy-columns / none sources. */
  chain: LifecycleAttestationView[];
  // Convenience fields for rendering, populated from whichever source won.
  withdrawnAt?: string;
  withdrawnReason?: string;
  reinstatedAt?: string;
  reinstatedReason?: string;
}

export interface AttestationVerifyResult {
  /** The recomputed envelope hash (= nodeId by construction). */
  nodeId: string;
  /** Recomputed envelope hash equals the stored nodeId. */
  nodeIdMatches: boolean;
  /** Ed25519ph signature verifies over the recomputed nodeId; null if unsigned. */
  signatureValid: boolean | null;
}

/**
 * Verify an attestation node independently (spec §8.10: "verify the corresponding
 * lifecycle signatures … for each attestation independently"). Recomputes the
 * envelope hash via the shared dual-chain `computeEnvelopeHash` and verifies the
 * signature over it.
 */
export function verifyAttestationNode(
  node: Record<string, unknown>,
  storedNodeId: string,
  sigEnvelope: { signature?: string; publicKey?: string; algorithm?: string } | null,
): AttestationVerifyResult {
  const recomputed = computeEnvelopeHash(node);
  const nodeIdMatches = recomputed === storedNodeId;
  let signatureValid: boolean | null = null;
  if (sigEnvelope?.signature && sigEnvelope?.publicKey) {
    signatureValid = verifySignature(
      recomputed,
      sigEnvelope.signature,
      sigEnvelope.publicKey,
      sigEnvelope.algorithm,
    );
  }
  return { nodeId: recomputed, nodeIdMatches, signatureValid };
}

/** Envelope-timestamp ascending, ties broken by nodeId lexicographic (§8.10.1). */
function compareLifecycleOrder(
  a: LifecycleAttestationView,
  b: LifecycleAttestationView,
): number {
  if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? -1 : 1;
  if (a.nodeId === b.nodeId) return 0;
  return a.nodeId < b.nodeId ? -1 : 1;
}

/**
 * Check #10 (chain path) — derive lifecycle status from a set of verified
 * attestation views (spec §8.10.1, §8.10.3). The current status is the latest
 * signer-matched lifecycle attestation by envelope timestamp: `withdraws` →
 * withdrawn, `reinstates` → active. Non-signer-matched attestations are kept in
 * the surfaced chain for transparency but do NOT move the status (retention
 * asymmetry, §8.10.3).
 */
export function resolveLifecycleFromChain(
  views: LifecycleAttestationView[],
): LifecycleResolution {
  const chain = views
    .filter((v) => LIFECYCLE_ATTESTATION_TYPES.includes(v.type))
    .slice()
    .sort(compareLifecycleOrder);

  const signerMatched = chain.filter((v) => v.signerMatchesTarget);
  const latest = signerMatched[signerMatched.length - 1];
  const status: LifecycleStatus =
    latest && latest.type === ATTESTATION_WITHDRAWS ? 'withdrawn' : 'active';

  const latestWithdraw = [...signerMatched]
    .reverse()
    .find((v) => v.type === ATTESTATION_WITHDRAWS);
  const latestReinstate = [...signerMatched]
    .reverse()
    .find((v) => v.type === ATTESTATION_REINSTATES);

  return {
    status,
    source: 'attestation-chain',
    chain,
    ...(latestWithdraw
      ? {
          withdrawnAt: latestWithdraw.effectiveAt ?? latestWithdraw.createdAt,
          withdrawnReason: latestWithdraw.reason,
        }
      : {}),
    ...(latestReinstate
      ? {
          reinstatedAt: latestReinstate.createdAt,
          reinstatedReason: latestReinstate.reason,
        }
      : {}),
  };
}

/**
 * Check #10 (legacy fallback) — derive lifecycle status from the pre-PR3
 * `withdrawnAt` / `reinstatedAt` columns (spec §8.10.4). Used when a content node
 * has no attestation envelopes. Withdrawn iff `withdrawnAt` is set and
 * `reinstatedAt` is not.
 */
export function resolveLifecycleFromLegacyColumns(columns: {
  withdrawnAt?: string | null;
  withdrawnReason?: string | null;
  reinstatedAt?: string | null;
  reinstatedReason?: string | null;
}): LifecycleResolution {
  if (!columns.withdrawnAt) {
    return { status: 'active', source: 'none', chain: [] };
  }
  const reinstated = !!columns.reinstatedAt;
  return {
    status: reinstated ? 'active' : 'withdrawn',
    source: 'legacy-columns',
    chain: [],
    withdrawnAt: columns.withdrawnAt,
    ...(columns.withdrawnReason ? { withdrawnReason: columns.withdrawnReason } : {}),
    ...(columns.reinstatedAt ? { reinstatedAt: columns.reinstatedAt } : {}),
    ...(columns.reinstatedReason
      ? { reinstatedReason: columns.reinstatedReason }
      : {}),
  };
}

/** A signed lifecycle attestation, carried in the bundle so the chain resolves with
 *  NO reference-implementation dependency (civic-ai-tools-website#119 P3). The server
 *  fetches these from the DB + blob; an offline verifier reads them from the bundle. */
export interface CarriedLifecycleNode {
  /** The signed attestation node JSON (the envelope) — recomputed + signature-checked. */
  node: Record<string, unknown>;
  /** The stored nodeId (envelope hash) the recomputed hash must match. */
  nodeId: string;
  /** The signature envelope over the node (`{signature, publicKey, algorithm}`). */
  signature?: { signature?: string; publicKey?: string; algorithm?: string } | null;
  /** Presence flags (surfaced; per-attestation TSA/Rekor depth is a follow-up). */
  hasTimestamp?: boolean;
  hasRekor?: boolean;
}

function pickString(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/**
 * Resolve lifecycle (#10) INDEPENDENTLY from carried signed attestation nodes —
 * the browser/offline path that reaches `source: 'attestation-chain'` with no
 * reference-implementation dependency (civic-ai-tools-website#119 P3).
 *
 * Unlike the server (whose DB query guarantees the rows target this node and whose
 * rows are platform-signed), an independent verifier must NOT trust the carrier, so
 * each node is gated before it can affect status:
 *   - REACHABILITY (§9.2 #13): `node.targetNodeId` MUST equal the content node's id;
 *     an attestation about a different node is not part of this lifecycle.
 *   - INTEGRITY: the recomputed envelope hash MUST equal the stored `nodeId`.
 *   - SIGNATURE: the Ed25519(ph) signature MUST verify over that hash.
 * A node failing any of these is EXCLUDED (a forged/tampered/misdirected transition
 * cannot move the status). Surviving nodes go to `resolveLifecycleFromChain`, which
 * applies the §8.10.3 retention asymmetry (a valid but non-signer-matched attestation
 * is surfaced in the chain yet does NOT move the publisher's status). That shared
 * resolver is unchanged, so the server route's output stays byte-identical.
 */
export function verifyLifecycleChain(
  carried: CarriedLifecycleNode[],
  contentNodeId: string,
  targetSignerIdentifier: string,
): LifecycleResolution {
  const views: LifecycleAttestationView[] = [];
  for (const entry of carried) {
    // Reachability: the attestation must reference THIS content node.
    if (pickString(entry.node['targetNodeId']) !== contentNodeId) continue;

    const verdict = verifyAttestationNode(entry.node, entry.nodeId, entry.signature ?? null);
    // Independent crypto gate: integrity + a valid signature, or it cannot count.
    if (!verdict.nodeIdMatches || verdict.signatureValid !== true) continue;

    const signer = entry.node['signer'] as SignerIdentity | undefined;
    const metadata = entry.node['metadata'] as Record<string, unknown> | undefined;
    views.push({
      nodeId: entry.nodeId,
      type: pickString(entry.node['type']) ?? '',
      signer,
      createdAt: pickString(metadata?.['createdAt']) ?? '',
      reason: pickString(entry.node['reason']),
      effectiveAt: pickString(entry.node['effectiveAt']),
      priorWithdrawalNodeId: pickString(entry.node['priorWithdrawalNodeId']),
      signatureValid: verdict.signatureValid,
      nodeIdMatches: verdict.nodeIdMatches,
      hasTimestamp: !!entry.hasTimestamp,
      hasRekor: !!entry.hasRekor,
      signerMatchesTarget: !!signer && signer.identifier === targetSignerIdentifier,
    });
  }
  return resolveLifecycleFromChain(views);
}
