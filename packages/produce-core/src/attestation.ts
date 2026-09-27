// Attestation node builder (spec §8.10, §8.12) — format-neutral, I/O-free,
// deterministic.
//
// An `attestation/*` node is a full signed envelope — its own nodeId
// (envelope hash), signature, timestamp, and transparency-log proof — that
// references a content node by `targetNodeId` and asserts something about it
// WITHOUT modifying it.
//
// This builder is the attestation analog of `buildEnvelope`: it produces the
// unsigned envelope + its nodeId, REUSING verify-core's canonicalization
// (RFC 8785 JCS envelope hash + multihash contentHash) so attestation nodes
// verify on the identical dual-chain logic. Signing / timestamping /
// submission / storage are caller steps, exactly as for content nodes.
//
// Determinism inputs (`packageId`, `createdAt`, `signingKeyId`) are
// caller-supplied — no RNG, no clock, no active-key probe in the core.

// The URIs of the sub-types verify-core checks (the withdraws/reinstates pair,
// `supersedes`, `revises`, `corroborates`, `contradicts`) are defined once in
// verify-core, which dispatches on them; imported for the builder body and
// re-exported so a producer needs a single import. `endorses` stays reserved
// name-only: nothing here emits it until the spec defines its role check
// (typedstandards#113 G0 D1).
import {
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  ATTESTATION_SUPERSEDES,
  ATTESTATION_REVISES,
  ATTESTATION_CORROBORATES,
  ATTESTATION_CONTRADICTS,
  LIFECYCLE_ATTESTATION_TYPES,
  LEGACY_JSON_CANONICALIZATION,
  computeContentHashSha256,
  computeEnvelopeHash,
  type LifecycleAttestationType,
  type SignerIdentity,
} from '@typedstandards/verify-core';

export {
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  ATTESTATION_SUPERSEDES,
  ATTESTATION_REVISES,
  ATTESTATION_CORROBORATES,
  ATTESTATION_CONTRADICTS,
  LIFECYCLE_ATTESTATION_TYPES,
  type LifecycleAttestationType,
};

// Publication-pair sub-types (spec §8.10, §8.12.1). Defined here (not in
// verify-core) because lifecycle resolution does not read them: verify-core's
// `resolveLifecycleFromChain` keeps withdraws, reinstates, supersedes and
// revises in the chain and reads the status from the first three only;
// publishes/locatedAt express the visibility dimension, which surfaces read
// directly from the chain.
export const ATTESTATION_PUBLISHES = 'attestation/publishes/v1';
export const ATTESTATION_LOCATED_AT = 'attestation/locatedAt/v1';

// Adversarial-evaluation sub-type (spec §8.12.1). Authorization rule:
// specific-role-required — an evaluator with a declared methodology and
// identity binding. The evaluator's binding lives on the envelope `signer`
// (spec §8.5), NOT duplicated in the payload.
export const ATTESTATION_EVALUATES = 'attestation/evaluates/v1';

/** The sub-types this builder can emit: the verify-core lifecycle pair,
 *  `supersedes` and `revises`, the claim-to-claim `corroborates` and
 *  `contradicts`, the publication pair, and the adversarial evaluation. */
export type EmittableAttestationType =
  | LifecycleAttestationType
  | typeof ATTESTATION_SUPERSEDES
  | typeof ATTESTATION_REVISES
  | typeof ATTESTATION_CORROBORATES
  | typeof ATTESTATION_CONTRADICTS
  | typeof ATTESTATION_PUBLISHES
  | typeof ATTESTATION_LOCATED_AT
  | typeof ATTESTATION_EVALUATES;

/** `corroborates` / `contradicts` payload: the optional `reasoning` (spec
 *  §8.12.1). The spec gives it no type; §8.12.2 puts a variance methodology and
 *  a result delta in it, so it is a string or a JSON object, emitted verbatim. */
export type AttestationReasoning = string | { [key: string]: unknown };

/** `evaluates` payload: methodology declaration (required content). */
export interface EvaluationMethodology {
  /** Test-set / rubric identifier (an adopter-scoped name). */
  testSet: string;
  /** Version of the rubric text — its SHA-256, so the exact prompt set is pinned. */
  promptSetVersion: string;
  /** Model identifier that performed the evaluation. */
  evaluatorModel: string;
}

/** `evaluates` payload: structured results. */
export interface EvaluationResults {
  perCriterion: Record<string, { score: number; comment: string }>;
  overallScore: number;
  assessment: string;
}

const PACKAGE_SCHEMA_VERSION = '0.1.0';

/**
 * A conformant `attestation/*` envelope (spec §8.12.3). Structurally a
 * content-like package: metadata + type + signer + contentCanonicalization +
 * contentHash, plus the attestation-specific `targetNodeId` and the sub-type
 * payload fields. `contentHash` is typed optional only so the builder can
 * compute it from the base object (a hash cannot include itself); it is
 * always present on a built node.
 */
export interface AttestationNode {
  metadata: {
    schemaVersion: string;
    packageId: string;
    createdAt: string;
    signingKeyId: string;
  };
  /** Attestation sub-type URI, e.g. `attestation/withdraws/v1`. */
  type: string;
  /** Envelope-side identity claim (spec §8.1.1, §8.5) — whoever the caller's
   *  key signs on behalf of. */
  signer?: SignerIdentity;
  /** The content node this attestation references by nodeId (spec §8.12.1). */
  targetNodeId: string;
  /** Off-log canonicalization rule. Attestation content is JSON, so always
   *  legacy-json/v1 (the whole-envelope-minus-contentHash rule). */
  contentCanonicalization: string;
  /** Multihash digest set fingerprinting the off-log content (spec §8.2). */
  contentHash?: Record<string, string>;
  // --- Sub-type payload (spec §8.12.1) ---
  /** `withdraws` (required, non-empty) / `reinstates` (optional). */
  reason?: string;
  /** `withdraws`: when the withdrawal takes effect (defaults to envelope ts). */
  effectiveAt?: string;
  /** `reinstates`: the prior withdrawal this reinstatement reverses. */
  priorWithdrawalNodeId?: string;
  /** `publishes`: the host the publication transitions visibility on. */
  publicationHost?: string;
  /** `publishes`: when the publication takes effect (defaults to envelope ts). */
  releasedAt?: string;
  /** `locatedAt`: the URI where the target's content is available. */
  uri?: string;
  /** `locatedAt`: multihash fingerprint of the TARGET's content (SHOULD match
   *  the target node's own `contentHash`). Named `targetContentHash` because
   *  the `contentHash` key is already taken by this envelope's own
   *  structural-primitive fingerprint. */
  targetContentHash?: Record<string, string>;
  /** `locatedAt`: byte length of the content at `uri` (optional). */
  contentLength?: number;
  /** `evaluates`: methodology declaration. */
  methodology?: EvaluationMethodology;
  /** `evaluates`: rubric identifier (per the §8.12.1 payload row). */
  scoringRubric?: string;
  /** `evaluates`: structured results. */
  results?: EvaluationResults;
  /** `supersedes`: the successor node (new); `revises`: this revision. */
  successorNodeId?: string;
  /** `corroborates` / `contradicts`: what of the target the attestation covers. */
  scope?: string;
  /** `corroborates` / `contradicts`: why (optional). */
  reasoning?: AttestationReasoning;
}

export interface AttestationInput {
  /** Deterministic envelope identity — caller-supplied (no RNG in the core). */
  packageId: string;
  /** Envelope timestamp (ISO 8601) — caller-supplied (no clock in the core).
   *  Also the §8.12.1 default for `effectiveAt` / `releasedAt`. */
  createdAt: string;
  /** Key identifier recorded in `metadata.signingKeyId` — caller-supplied. */
  signingKeyId: string;
  type: EmittableAttestationType;
  targetNodeId: string;
  signer: SignerIdentity;
  reason?: string;
  effectiveAt?: string;
  priorWithdrawalNodeId?: string;
  publicationHost?: string;
  releasedAt?: string;
  uri?: string;
  targetContentHash?: Record<string, string>;
  contentLength?: number;
  methodology?: EvaluationMethodology;
  scoringRubric?: string;
  results?: EvaluationResults;
  successorNodeId?: string;
  scope?: string;
  reasoning?: AttestationReasoning;
}

/**
 * Build an unsigned attestation envelope and its nodeId.
 *
 * The nodeId is the RFC 8785 JCS envelope hash (spec §8.2/§8.3.1) — the same
 * `computeEnvelopeHash` the content packager uses, so attestation nodes
 * verify on the identical dual-chain logic. The off-log content hash is
 * computed under legacy-json/v1 from the envelope minus `contentHash`, then
 * spread on last. An unsigned node is a complete, first-class result.
 */
export function buildAttestationNode(
  input: AttestationInput,
): { node: AttestationNode; nodeId: string } {
  // Base envelope WITHOUT contentHash. The conditional spreads keep the
  // payload minimal — only supplied sub-type fields are emitted, so the
  // canonical JSON carries exactly the fields the sub-type defines.
  const base: AttestationNode = {
    metadata: {
      schemaVersion: PACKAGE_SCHEMA_VERSION,
      packageId: input.packageId,
      createdAt: input.createdAt,
      signingKeyId: input.signingKeyId,
    },
    type: input.type,
    signer: input.signer,
    targetNodeId: input.targetNodeId,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    ...(input.reason !== undefined ? { reason: input.reason } : {}),
    // `effectiveAt` defaults to the envelope timestamp per §8.12.1.
    ...(input.type === ATTESTATION_WITHDRAWS
      ? { effectiveAt: input.effectiveAt ?? input.createdAt }
      : {}),
    ...(input.priorWithdrawalNodeId !== undefined
      ? { priorWithdrawalNodeId: input.priorWithdrawalNodeId }
      : {}),
    // `publishes` payload (§8.12.1): publicationHost + releasedAt (defaults
    // to the envelope timestamp, mirroring effectiveAt's rule).
    ...(input.type === ATTESTATION_PUBLISHES
      ? {
          publicationHost: input.publicationHost,
          releasedAt: input.releasedAt ?? input.createdAt,
        }
      : {}),
    // `locatedAt` payload (§8.12.1): uri + target fingerprint (+ optional
    // length).
    ...(input.uri !== undefined ? { uri: input.uri } : {}),
    ...(input.targetContentHash !== undefined
      ? { targetContentHash: input.targetContentHash }
      : {}),
    ...(input.contentLength !== undefined
      ? { contentLength: input.contentLength }
      : {}),
    // `evaluates` payload (§8.12.1): methodology + scoringRubric + results.
    ...(input.methodology !== undefined ? { methodology: input.methodology } : {}),
    ...(input.scoringRubric !== undefined ? { scoringRubric: input.scoringRubric } : {}),
    ...(input.results !== undefined ? { results: input.results } : {}),
    // `supersedes` / `revises` payload (§8.12.1): the successor node.
    ...(input.successorNodeId !== undefined
      ? { successorNodeId: input.successorNodeId }
      : {}),
    // `corroborates` / `contradicts` payload (§8.12.1): scope + optional
    // reasoning, a string or a JSON object, emitted verbatim.
    ...(input.scope !== undefined ? { scope: input.scope } : {}),
    ...(input.reasoning !== undefined ? { reasoning: input.reasoning } : {}),
  };

  const contentHash = {
    sha256: computeContentHashSha256(
      base as unknown as Record<string, unknown>,
      LEGACY_JSON_CANONICALIZATION,
    ),
  };
  const node: AttestationNode = { ...base, contentHash };
  const nodeId = computeEnvelopeHash(node as unknown as Record<string, unknown>);

  return { node, nodeId };
}
