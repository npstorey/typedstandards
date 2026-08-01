// Commitment-view ("proof sidecar") builder (spec §8.8.1, §9.2.1) —
// format-neutral, I/O-free.
//
// The self-describing proof carrier of spec §9.4: everything an independent
// verifier needs to bootstrap the §9.2 checks from one object — the envelope
// hash, the VERBATIM signature envelope, the external-proof material
// (RFC 3161 token, Rekor entry / inclusion proof / canonical body), the
// signed envelope claims, an optional carried lifecycle chain, and the
// publisher's trust-registry URL.
//
// Every value is caller-supplied. `trustRegistryUrl` is per-publisher
// CONFIGURATION — deliberately a required input, never a constant, so a
// prospective adopter's registry travels with its proofs. The signature
// envelope is carried verbatim (including `algorithm` and `kid`): `algorithm`
// is load-bearing for the verifier's Ed25519/Ed25519ph dispatch, and `kid` is
// the trust-registry lookup handle; both may be absent on packages signed via
// an older path and are carried as-is.
//
// Mapping storage rows / records onto this input is implementation-side
// adapter work; the core defines the shape and the conditional-emission rules
// (absent proofs are omitted, never emitted as null).

import type {
  CarriedLifecycleNode,
  SignerIdentity,
} from '@typedstandards/verify-core';

const EVIDENCE_PROTOCOL_VERSION = '0.1.0';

/**
 * Current lifecycle state of the content node, surfaced alongside the proofs
 * so an independent verifier can render a withdrawn state without a separate
 * lookup. A withdrawn package's base signature still verifies (withdrawal is
 * a separate, separately-signed action) — this is informational state.
 * Derivation from an implementation's stored columns is caller work.
 */
export interface CommitmentLifecycle {
  status: 'active' | 'withdrawn';
  withdrawnAt?: string;
  withdrawnReason?: string;
  reinstatedAt?: string;
  reinstatedReason?: string;
}

/** Neutral input to `buildCommitmentView` — the caller-supplied proof fields. */
export interface CommitmentViewInput {
  /** The package's envelope hash (spec §8.2) — the commitment's subject. */
  packageHash: string;
  /** Where the canonical package JSON is retrievable. Omit when unknown;
   *  never emitted on a redacted view (a non-derivable capability URL must
   *  not be disclosed for committed-visibility records). */
  packageUrl?: string;
  /** Visibility state; defaults to `published` (the shape's legacy default),
   *  letting a verifier render a committed / not-publicly-located state
   *  honestly instead of treating a missing packageUrl as an error. */
  visibility?: string;
  /** Capture-method label; `null` (emitted) when the record predates it. */
  captureMethod?: string | null;
  /** Content-profile label; defaults to `default`. */
  contentProfile?: string | null;
  // Envelope fields sourced from the signed package JSON (spec §8.1.1). All
  // covered by the package signature; conditionally emitted so packages
  // predating them omit them rather than emitting nulls.
  producerProfile?: string;
  type?: string;
  signer?: SignerIdentity;
  contentHash?: Record<string, string>;
  contentCanonicalization?: string;
  /** VERBATIM signature envelope (`{signature, publicKey, algorithm, kid}`). */
  signature?: Record<string, unknown> | null;
  /** Optional informational identity block about the record's creator —
   *  opaque to the core; NOT the verify-check subject (that is the envelope's
   *  `signer` claim above). */
  signerIdentity?: Record<string, unknown> | null;
  /** RFC 3161 timestamp token (base64). */
  rfc3161Timestamp?: string;
  /** Rekor entry id / inclusion proof (JSON string) / canonical leaf body
   *  (base64) — carried so inclusion verifies OFFLINE. */
  rekorEntryId?: string;
  rekorInclusionProof?: string;
  rekorEntryBody?: string;
  /** Informational lifecycle summary; omit when the package has no lifecycle
   *  history. */
  lifecycle?: CommitmentLifecycle | null;
  /** Signed lifecycle attestation envelopes, carried so an independent
   *  verifier resolves the lifecycle chain offline via verify-core's
   *  `verifyLifecycleChain`. Omitted when empty. */
  lifecycleAttestations?: readonly CarriedLifecycleNode[];
  /** REQUIRED per-publisher configuration (spec §8.3.3): where the
   *  publisher's public keys resolve. Never a constant in the core. */
  trustRegistryUrl: string;
  /** Optional secondary registry path served byte-identical to the canonical
   *  one, for clients that only know an older path. */
  trustRegistryUrlLegacy?: string;
  /** Content-derived display strings — redacted for committed records. Pass
   *  `null` to emit an explicit JSON null. */
  subjectTitle?: string | null;
  subjectSummary?: string | null;
  /** Committed-record redaction: the commitment is public by design (the
   *  hash is already on the transparency log), but the content's location and
   *  content-derived strings are not. When set, the view omits `packageUrl`,
   *  `subjectTitle`, and `subjectSummary`; proof-side fields are served
   *  unredacted — they ARE the commitment. */
  redactContentSurface?: boolean;
}

/**
 * Build the spec §8.8.1 / §9.2.1 commitment view from caller-supplied proof
 * fields. Optional fields are conditionally spread so absent values don't
 * appear as `null` in the serialized output; emission order matches the
 * reference shape.
 */
export function buildCommitmentView(
  input: CommitmentViewInput,
): Record<string, unknown> {
  if (!input.trustRegistryUrl) {
    throw new Error(
      'buildCommitmentView requires trustRegistryUrl — per-publisher configuration is caller-supplied, never a core constant',
    );
  }
  const redact = input.redactContentSurface === true;

  return {
    evidenceProtocolVersion: EVIDENCE_PROTOCOL_VERSION,
    packageHash: input.packageHash,
    // The content's location is never emitted on a redacted view.
    ...(redact || input.packageUrl === undefined
      ? {}
      : { packageUrl: input.packageUrl }),
    visibility: input.visibility ?? 'published',
    captureMethod: input.captureMethod ?? null,
    contentProfile: input.contentProfile ?? 'default',
    // Signed envelope claims (spec §8.1.1) — conditionally spread.
    ...(input.producerProfile ? { producerProfile: input.producerProfile } : {}),
    ...(input.type ? { type: input.type } : {}),
    ...(input.signer ? { signer: input.signer } : {}),
    ...(input.contentHash ? { contentHash: input.contentHash } : {}),
    ...(input.contentCanonicalization
      ? { contentCanonicalization: input.contentCanonicalization }
      : {}),
    ...(input.signature ? { signature: input.signature } : {}),
    ...(input.signerIdentity ? { signerIdentity: input.signerIdentity } : {}),
    ...(input.rfc3161Timestamp
      ? { rfc3161Timestamp: input.rfc3161Timestamp }
      : {}),
    ...(input.rekorEntryId ? { rekorEntryId: input.rekorEntryId } : {}),
    ...(input.rekorInclusionProof
      ? { rekorInclusionProof: input.rekorInclusionProof }
      : {}),
    ...(input.rekorEntryBody ? { rekorEntryBody: input.rekorEntryBody } : {}),
    ...(input.lifecycle ? { lifecycle: input.lifecycle } : {}),
    ...(input.lifecycleAttestations?.length
      ? { lifecycleAttestations: input.lifecycleAttestations }
      : {}),
    trustRegistryUrl: input.trustRegistryUrl,
    ...(input.trustRegistryUrlLegacy
      ? { trustRegistryUrlLegacy: input.trustRegistryUrlLegacy }
      : {}),
    // Content-derived strings — redacted for committed records.
    ...(redact
      ? {}
      : { subjectTitle: input.subjectTitle, subjectSummary: input.subjectSummary }),
  };
}
