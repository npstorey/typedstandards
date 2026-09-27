// Lifecycle attestation checks (spec §9.2 check #10, §8.10) — browser-safe pure
// logic.
//
// Lifecycle state (active / withdrawn / superseded) is derived from a chain of
// separately-signed `attestation/*` nodes referencing the content node by
// `targetNodeId`, each verified independently. Backwards-compat (§8.10.4): when
// no attestation envelopes are present, the legacy `withdrawnAt` /
// `reinstatedAt` columns are honored instead.
//
// This file holds only the PURE ordering / status-derivation / per-node
// verification logic (factored from the server `verify.ts`). The DB + blob fetch
// orchestration that assembles the chain stays in the server `lifecycle.ts`,
// which imports these. WS2's portable orchestrator (`verify.ts` →
// `verifyRecord`) consumes lifecycle at STATE depth (the sidecar's
// status/withdrawnAt/reason) rather than re-running the chain — verifying the
// signed attestation chain independently in the browser is civic-ai-tools-website#119.

import { computeEnvelopeHash } from './canonicalization.ts';
import { extractRawPublicKey, verifySignature } from './signature.ts';
import { checkSignerIdentity } from './checks.ts';
import { isKeyDerivedIdentifier } from './did-key.ts';
import { verifyKeyTrust } from './trust-registry.ts';
import {
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  ATTESTATION_SUPERSEDES,
  ATTESTATION_REVISES,
  ATTESTATION_CORROBORATES,
  ATTESTATION_CONTRADICTS,
  LIFECYCLE_STATUS_ATTESTATION_TYPES,
  LIFECYCLE_CHAIN_ATTESTATION_TYPES,
} from './attestation.ts';
import type { SignerIdentity } from './types.ts';
import type { TrustRegistry, TrustRegistryProvenance } from './trust-registry.ts';

/** Lifecycle status (spec §8.10.6). Only the attestation chain derives
 *  `superseded`; the legacy columns (§8.10.4) know no supersession. */
export const LIFECYCLE_STATUSES = ['active', 'withdrawn', 'superseded'] as const;
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
  /** `supersedes` / `revises`: the successor node's id. */
  successorNodeId?: string;
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
  /** Whether the node counts toward the status (§8.12.3). The attestation's
   *  signer.identifier matches the target content node's signer.identifier. On a
   *  view built by `verifyLifecycleChain`, it also requires `keyBound`, and that the
   *  node carries every payload field §8.12.1 requires of its sub-type
   *  (`missingFields` empty): §8.12.3's conformance covers the payload fields. */
  signerMatchesTarget: boolean;
  /** Set by `verifyLifecycleChain`: the node's signing key is bound to the
   *  signer it names (see `verifyLifecycleChain`). Absent on views built
   *  elsewhere. */
  keyBound?: boolean;
  /** Set by `verifyLifecycleChain`: the node's `signer.identifier` equals the
   *  target's, whether or not its key is bound. Absent on views built elsewhere. */
  namesTarget?: boolean;
  /** Set by `verifyLifecycleChain`: each payload field §8.12.1 requires of the
   *  node's sub-type (`ATTESTATION_REQUIRED_FIELDS`) that the node lacks (absent,
   *  null or the empty string), by name; empty when it lacks none. A node that
   *  lacks one does not count toward the status. Absent on views built elsewhere. */
  missingFields?: string[];
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
  /** The latest counting `supersedes`: its envelope timestamp. */
  supersededAt?: string;
  /** The latest counting `supersedes`: its `successorNodeId`. */
  successorNodeId?: string;
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
 * attestation views (spec §8.10.1, §8.10.3, §8.10.6; typedstandards#113 G0 D2).
 *
 * The chain holds the publisher-only lifecycle sub-types
 * (`LIFECYCLE_CHAIN_ATTESTATION_TYPES`: withdraws, reinstates, supersedes,
 * revises), ordered by envelope timestamp, ties by nodeId. The status is read
 * from the latest signer-matched node among withdraws, reinstates and
 * supersedes (`LIFECYCLE_STATUS_ATTESTATION_TYPES`):
 *   - `withdraws` → withdrawn;
 *   - `supersedes` → superseded;
 *   - `reinstates` → superseded when a signer-matched `supersedes` precedes it in
 *     chain order, active otherwise.
 * `revises` is surfaced in the chain and never moves the status (§8.10.5: no
 * deprecation signal). Non-signer-matched attestations are kept in the surfaced
 * chain for transparency but do NOT move the status (retention asymmetry,
 * §8.10.3). The latest signer-matched `supersedes` names the successor and the
 * supersession time.
 *
 * For a chain of withdraws and reinstates only, the output is what it was before
 * `superseded` existed.
 */
export function resolveLifecycleFromChain(
  views: LifecycleAttestationView[],
): LifecycleResolution {
  const chain = views
    .filter((v) => LIFECYCLE_CHAIN_ATTESTATION_TYPES.includes(v.type))
    .slice()
    .sort(compareLifecycleOrder);

  const signerMatched = chain.filter(
    (v) => v.signerMatchesTarget && LIFECYCLE_STATUS_ATTESTATION_TYPES.includes(v.type),
  );
  const latest = signerMatched[signerMatched.length - 1];
  const latestSupersede = [...signerMatched]
    .reverse()
    .find((v) => v.type === ATTESTATION_SUPERSEDES);

  let status: LifecycleStatus = 'active';
  if (latest?.type === ATTESTATION_WITHDRAWS) status = 'withdrawn';
  else if (latest?.type === ATTESTATION_SUPERSEDES) status = 'superseded';
  // A reinstatement returns the node to where it stood before the withdrawal:
  // superseded if a counting supersedes precedes it, which it does whenever one
  // exists, since the reinstatement is the latest counting node.
  else if (latest?.type === ATTESTATION_REINSTATES && latestSupersede) status = 'superseded';

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
    ...(latestSupersede
      ? {
          supersededAt: latestSupersede.createdAt,
          ...(latestSupersede.successorNodeId
            ? { successorNodeId: latestSupersede.successorNodeId }
            : {}),
        }
      : {}),
  };
}

/**
 * Check #10 (legacy fallback) — derive lifecycle status from the pre-PR3
 * `withdrawnAt` / `reinstatedAt` columns (spec §8.10.4). Used when a content node
 * has no attestation envelopes. Withdrawn iff `withdrawnAt` is set and
 * `reinstatedAt` is not. It never derives `superseded`: the columns record no
 * supersession.
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
  signature?: { signature?: string; publicKey?: string; algorithm?: string; kid?: string } | null;
  /** Presence flags (surfaced; per-attestation TSA/Rekor depth is a follow-up). */
  hasTimestamp?: boolean;
  hasRekor?: boolean;
}

/** What a caller holds that can bind a lifecycle attestation's signing key to
 *  the signer it names (see `verifyLifecycleChain`). */
export interface LifecycleKeyBinding {
  /** The target record's own signing key (the base64 SPKI `publicKey` of its
   *  signature envelope). */
  targetPublicKey?: string;
  /** A parsed trust registry. */
  registry?: TrustRegistry;
  /** Where `registry` came from. Only `declared-url` can bind a key; absent is
   *  treated as `bundle`. */
  registryProvenance?: TrustRegistryProvenance;
}

function pickString(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function sameKey(a: string, b: string): boolean {
  try {
    const x = extractRawPublicKey(a);
    const y = extractRawPublicKey(b);
    return x.length === y.length && x.every((byte, i) => byte === y[i]);
  } catch {
    return false;
  }
}

/**
 * Whether a lifecycle attestation's signing key is bound to the signer it names.
 *   - A key-derived identifier (`did:key:`) binds by derivation from `publicKey`,
 *     under the rule check #14 applies to a record: it binds when #14 reads
 *     `key_derived_match`.
 *   - Any other identifier binds when `publicKey` is the target record's own
 *     signing key, or when a registry fetched from its declared URL lists it
 *     under that identifier: check #14 reads `ok` for the node's `kid`, and
 *     check #5 reads the `(kid, publicKey)` pair as verified. The node carries
 *     no verified signing time, so a deprecated key does not bind.
 * A registry carried in a bundle, or one with no stated provenance, never binds.
 */
function isKeyBound(
  node: Record<string, unknown>,
  publicKey: string,
  kid: string | undefined,
  binding: LifecycleKeyBinding,
): boolean {
  const signer = node['signer'] as SignerIdentity | undefined;
  if (!signer || typeof signer !== 'object' || typeof signer.identifier !== 'string') return false;
  if (isKeyDerivedIdentifier(signer.identifier)) {
    return checkSignerIdentity(node, kid, binding.registry, publicKey).status === 'key_derived_match';
  }
  if (binding.targetPublicKey && sameKey(publicKey, binding.targetPublicKey)) return true;
  if (!kid || !binding.registry || binding.registryProvenance !== 'declared-url') return false;
  if (checkSignerIdentity(node, kid, binding.registry).status !== 'ok') return false;
  return verifyKeyTrust(publicKey, kid, undefined, binding.registry).verified;
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
 * cannot move the status). A surviving node is signer-matched only when its
 * `signer.identifier` equals the target's AND its signing key is bound to that
 * identifier (`keyBound`), by what `binding` supplies:
 *   - a key-derived identifier (`did:key:`) binds by derivation from the node's own
 *     public key, the rule check #14 applies to a record;
 *   - any other identifier binds by `binding.targetPublicKey` (the node is signed by
 *     the target record's own key), or by `binding.registry` when
 *     `binding.registryProvenance` is `declared-url` and it lists the node's
 *     `(kid, publicKey)` under that identifier, read by the rules of checks #5 and
 *     #14. A registry carried in a bundle, or with no stated provenance, never binds.
 * Each view records `namesTarget` (the identifiers are equal) beside `keyBound`, so a
 * reader can tell a third party's node from one that names the publisher under a key
 * not bound to it.
 * A surviving node that lacks a payload field §8.12.1 requires of its sub-type
 * (§8.12.3; `ATTESTATION_REQUIRED_FIELDS`, absent, null or the empty string) is not
 * signer-matched either, whoever signed it: it stays in the chain, names the fields
 * in `missingFields`, and does not move the status.
 * Surviving nodes go to `resolveLifecycleFromChain`, which applies the §8.10.3
 * retention asymmetry (a valid but non-signer-matched attestation is surfaced in the
 * chain yet does NOT move the publisher's status).
 */
export function verifyLifecycleChain(
  carried: CarriedLifecycleNode[],
  contentNodeId: string,
  targetSignerIdentifier: string,
  binding: LifecycleKeyBinding = {},
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
    const keyBound = isKeyBound(
      entry.node,
      entry.signature?.publicKey ?? '',
      pickString(entry.signature?.kid),
      binding,
    );
    const namesTarget = !!signer && signer.identifier === targetSignerIdentifier;
    const type = pickString(entry.node['type']) ?? '';
    const missingFields = missingRequiredFields(entry.node, type);
    views.push({
      nodeId: entry.nodeId,
      type,
      signer,
      createdAt: pickString(metadata?.['createdAt']) ?? '',
      reason: pickString(entry.node['reason']),
      effectiveAt: pickString(entry.node['effectiveAt']),
      priorWithdrawalNodeId: pickString(entry.node['priorWithdrawalNodeId']),
      successorNodeId: pickString(entry.node['successorNodeId']),
      signatureValid: verdict.signatureValid,
      nodeIdMatches: verdict.nodeIdMatches,
      hasTimestamp: !!entry.hasTimestamp,
      hasRekor: !!entry.hasRekor,
      signerMatchesTarget: namesTarget && keyBound && missingFields.length === 0,
      keyBound,
      namesTarget,
      missingFields,
    });
  }
  return resolveLifecycleFromChain(views);
}

// ---------------------------------------------------------------------------
// The per-node authorization check (spec §8.12.3; typedstandards#113 G0 D6 as
// corrected, and D4)

/** A sub-type's authorization rule (spec §8.12.1). */
export type AttestationAuthorizationRule = 'publisher-only' | 'any-with-binding';

/** The rule of each sub-type `checkAttestationNode` checks. `publishes`,
 *  `locatedAt` and the specific-role-required sub-types have none here. */
export const ATTESTATION_AUTHORIZATION_RULES: Readonly<Record<string, AttestationAuthorizationRule>> = Object.freeze({
  [ATTESTATION_WITHDRAWS]: 'publisher-only',
  [ATTESTATION_REINSTATES]: 'publisher-only',
  [ATTESTATION_SUPERSEDES]: 'publisher-only',
  [ATTESTATION_REVISES]: 'publisher-only',
  [ATTESTATION_CORROBORATES]: 'any-with-binding',
  [ATTESTATION_CONTRADICTS]: 'any-with-binding',
});

/** Each checked sub-type's required payload fields (spec §8.12.1), beyond the
 *  structural primitive. Optional fields (`effectiveAt`, a reinstatement's
 *  `reason`, `reasoning`) are not listed. */
export const ATTESTATION_REQUIRED_FIELDS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  [ATTESTATION_WITHDRAWS]: ['targetNodeId', 'reason'],
  [ATTESTATION_REINSTATES]: ['targetNodeId', 'priorWithdrawalNodeId'],
  [ATTESTATION_SUPERSEDES]: ['targetNodeId', 'successorNodeId'],
  [ATTESTATION_REVISES]: ['targetNodeId', 'successorNodeId'],
  [ATTESTATION_CORROBORATES]: ['targetNodeId', 'scope'],
  [ATTESTATION_CONTRADICTS]: ['targetNodeId', 'scope'],
});

/** The `signer.bindingTier` values an any-with-binding node may carry: the §8.5
 *  graded identity ladder, and `platform` (spec §8.1.1). */
export const BINDING_TIERS = ['pseudonymous', 'oauth', 'orcid', 'did-web', 'notarized', 'platform'] as const;

/**
 * What `checkAttestationNode` reads for a node, first failure first:
 *   - `node_id_mismatch` — the recomputed envelope hash is not the stored nodeId;
 *   - `signature_invalid` — the signature does not verify over it;
 *   - `unsigned` — the node carries no signature, so nothing can be bound;
 *   - `not_checked` — publisher-only with no attested record supplied, or a
 *     sub-type this check has no rule for;
 *   - `other_signer` — publisher-only: the node names a signer other than the
 *     attested record's, a third party's event;
 *   - `publisher_key_unbound` — publisher-only: the node names the attested
 *     record's signer, but its signing key is not bound to that signer;
 *   - `key_unbound` — any-with-binding: the signing key is not bound to the signer
 *     the node names;
 *   - `binding_tier_off_ladder` — any-with-binding: `signer.bindingTier` is not in
 *     `BINDING_TIERS`;
 *   - `authorized` — the sub-type's rule holds.
 */
export const ATTESTATION_AUTHORIZATION_STATUSES = [
  'authorized',
  'not_checked',
  'other_signer',
  'publisher_key_unbound',
  'key_unbound',
  'binding_tier_off_ladder',
  'unsigned',
  'signature_invalid',
  'node_id_mismatch',
] as const;
export type AttestationAuthorizationStatus = (typeof ATTESTATION_AUTHORIZATION_STATUSES)[number];

/** What a caller holds for `checkAttestationNode`. */
export interface AttestationCheckContext {
  /** The attested record: its `signer.identifier`, and the base64 SPKI
   *  `publicKey` of its signature envelope. The publisher-only rule runs only
   *  when this is supplied. */
  target?: { signerIdentifier: string; publicKey: string };
  /** A parsed trust registry that may bind the node's key to the identifier it
   *  names. */
  registry?: TrustRegistry;
  /** Where `registry` came from. Only `declared-url` can bind a key; absent is
   *  treated as `bundle`. */
  registryProvenance?: TrustRegistryProvenance;
}

export interface AttestationCheck {
  /** The recomputed envelope hash. */
  nodeId: string;
  type: string;
  /** The sub-type's rule; null for a sub-type this check has none for. */
  rule: AttestationAuthorizationRule | null;
  nodeIdMatches: boolean;
  signatureValid: boolean | null;
  /** The signing key is bound to the signer the node names (see `status`). */
  keyBound: boolean;
  status: AttestationAuthorizationStatus;
  /** Each required §8.12.1 payload field the node lacks (absent, null or the
   *  empty string), by name. Reported only; it does not change `status`. */
  missingFields: string[];
}

function isAbsent(v: unknown): boolean {
  return v === undefined || v === null || v === '';
}

/** Each payload field §8.12.1 requires of `type` that `node` lacks, by name. */
function missingRequiredFields(node: Record<string, unknown>, type: string): string[] {
  return (ATTESTATION_REQUIRED_FIELDS[type] ?? []).filter((f) => isAbsent(node[f]));
}

/**
 * Check one `attestation/*` node on its own (spec §8.12.3), for `withdraws`,
 * `reinstates`, `supersedes`, `revises`, `corroborates` and `contradicts`, in
 * order:
 *   1. integrity and signature, as `verifyAttestationNode` reads them;
 *   2. the key binding, by the rule `verifyLifecycleChain` applies: a key-derived
 *      identifier binds by derivation; any other identifier binds by a registry
 *      fetched from its declared URL, and, for a publisher-only node only, by the
 *      attested record's own signing key;
 *   3. the sub-type's authorization rule:
 *      - publisher-only (the four lifecycle sub-types) runs when `context.target`
 *        is supplied, and otherwise reads `not_checked`. A node naming another
 *        signer reads `other_signer`; one naming the target's signer under a key
 *        not bound to it reads `publisher_key_unbound`;
 *      - any-with-binding (`corroborates`, `contradicts`) needs the key bound and a
 *        `signer.bindingTier` in `BINDING_TIERS`.
 * It also names each required §8.12.1 payload field the node lacks. Pure; it moves
 * no status: `resolveLifecycleFromChain` alone derives the lifecycle.
 */
export function checkAttestationNode(
  carried: CarriedLifecycleNode,
  context: AttestationCheckContext = {},
): AttestationCheck {
  const node = carried.node;
  const type = pickString(node['type']) ?? '';
  const rule = ATTESTATION_AUTHORIZATION_RULES[type] ?? null;
  const verdict = verifyAttestationNode(node, carried.nodeId, carried.signature ?? null);
  const missingFields = missingRequiredFields(node, type);
  const publicKey = carried.signature?.publicKey ?? '';
  const signed = verdict.nodeIdMatches && verdict.signatureValid === true;
  const keyBound =
    signed &&
    isKeyBound(node, publicKey, pickString(carried.signature?.kid), {
      ...(rule === 'publisher-only' && context.target ? { targetPublicKey: context.target.publicKey } : {}),
      ...(context.registry ? { registry: context.registry } : {}),
      ...(context.registryProvenance ? { registryProvenance: context.registryProvenance } : {}),
    });
  const result = (status: AttestationAuthorizationStatus): AttestationCheck => ({
    nodeId: verdict.nodeId,
    type,
    rule,
    nodeIdMatches: verdict.nodeIdMatches,
    signatureValid: verdict.signatureValid,
    keyBound,
    status,
    missingFields,
  });

  if (!verdict.nodeIdMatches) return result('node_id_mismatch');
  if (verdict.signatureValid === false) return result('signature_invalid');
  if (verdict.signatureValid === null) return result('unsigned');
  if (rule === null) return result('not_checked');

  const signer = node['signer'] as SignerIdentity | undefined;
  const identifier = signer && typeof signer === 'object' ? signer.identifier : undefined;
  if (rule === 'publisher-only') {
    if (!context.target) return result('not_checked');
    if (identifier !== context.target.signerIdentifier) return result('other_signer');
    return result(keyBound ? 'authorized' : 'publisher_key_unbound');
  }
  if (!keyBound) return result('key_unbound');
  const tier = signer && typeof signer === 'object' ? signer.bindingTier : undefined;
  if (!(BINDING_TIERS as readonly unknown[]).includes(tier)) return result('binding_tier_off_ladder');
  return result('authorized');
}
