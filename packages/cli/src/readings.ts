// How each check's result reads (typedstandards#109 G0 D3). `verify` exits 1 when
// any check reads `alarm`; `attention` readings print on stderr and do not fail.
//
// The tiers are COPIED from typedstandards.org's verifier, so the CLI and the site
// give one record one verdict: apps/web/src/lib/trust-signal.ts at 0bb0527, the
// table named beside each map below. verify-core exports no classification of its
// own; moving one shared table into verify-core is a candidate for a later core
// minor (#109 G0 ruling, note 2). Each map is keyed by verify-core's status union,
// so a status verify-core adds fails this file's typecheck until it is classified.
//
// Not classified here, because nothing `sign` or `view` emits carries them, and
// `verify` refuses any input key they do not emit: check #7 (an RFC 3161 token)
// and check #8 (a transparency-log entry).

import {
  verifyAttestationNode,
  type BlobRefVerifyReason,
  type CaptureMethodVocabStatus,
  type ContentCanonicalizationStatus,
  type ContentHashStatus,
  type ContentProfileStatus,
  type KeyTrustStatus,
  type SignerIdentityCheckStatus,
  type SigningKeyIdConsistencyStatus,
  type TypeResolutionStatus,
  type VerifyResult,
} from '@typedstandards/verify-core';

export type Tier = 'verified' | 'normal' | 'attention' | 'alarm';

/** One check's reading: its specification number, the result field, its status, and the tier. */
export interface Reading {
  check: string;
  field: string;
  status: string;
  tier: Tier;
}

// ENVELOPE_INTEGRITY_* and resolveEnvelopeIntegrity, trust-signal.ts:134-181.
const ENVELOPE_INTEGRITY = {
  verified: 'verified',
  altered: 'alarm',
  'unavailable:private': 'normal',
  'unavailable:unfetchable': 'attention',
} as const satisfies Record<string, Tier>;

// SIGNATURE_SIGNALS, trust-signal.ts:185.
const SIGNATURE = { true: 'verified', false: 'alarm', null: 'normal' } as const satisfies Record<string, Tier>;

// CONTENT_CANONICALIZATION_SIGNALS, trust-signal.ts:207.
const CONTENT_CANONICALIZATION: Record<ContentCanonicalizationStatus, Tier> = {
  ok: 'verified',
  implicit: 'normal',
  unknown_canonicalization_rule: 'attention',
};

// CONTENT_HASH_SIGNALS, trust-signal.ts:228.
const CONTENT_HASH: Record<ContentHashStatus, Tier> = {
  ok: 'verified',
  legacy_relabeled: 'normal',
  content_hash_mismatch: 'alarm',
  unresolved_rule: 'attention',
  contentHash_no_supported_algorithm: 'attention',
  content_bytes_unavailable: 'attention',
};

// KEY_TRUST_SIGNALS, trust-signal.ts:283.
const KEY_TRUST: Record<KeyTrustStatus, Tier> = {
  active: 'verified',
  deprecated_valid: 'normal',
  deprecated_invalid: 'alarm',
  revoked: 'alarm',
  unknown_key: 'attention',
  registry_unavailable: 'attention',
  legacy_embedded: 'normal',
  self_certified: 'normal',
};

// SIGNING_KEY_ID_SIGNALS, trust-signal.ts:402.
const SIGNING_KEY_ID: Record<SigningKeyIdConsistencyStatus, Tier> = {
  ok: 'verified',
  signingKeyId_mismatch: 'alarm',
  signingKeyId_absent: 'attention',
  kid_absent: 'normal',
};

// BLOB_REF_REASON_SIGNALS, trust-signal.ts:678 (a reference that verifies reads
// `verified`, BLOB_REFS_SIGNALS, trust-signal.ts:608).
const BLOB_REF_REASON: Record<BlobRefVerifyReason, Tier> = {
  invalid_ref: 'alarm',
  fetch_failed: 'attention',
  size_mismatch: 'alarm',
  hash_mismatch: 'alarm',
};

// LIFECYCLE_ATTESTATION_NODE_ID_SIGNALS, trust-signal.ts:763, and
// LIFECYCLE_ATTESTATION_SIGNATURE_SIGNALS, trust-signal.ts:750.
const LIFECYCLE_NODE_ID = { true: 'verified', false: 'alarm' } as const satisfies Record<string, Tier>;
const LIFECYCLE_SIGNATURE = SIGNATURE;

// TYPE_RESOLUTION_SIGNALS, trust-signal.ts:839.
const TYPE_RESOLUTION: Record<TypeResolutionStatus, Tier> = {
  ok: 'verified',
  implicit: 'normal',
  unknown_type: 'attention',
};

// SIGNER_IDENTITY_SIGNALS, trust-signal.ts:855.
const SIGNER_IDENTITY: Record<SignerIdentityCheckStatus, Tier> = {
  ok: 'verified',
  signer_identity_mismatch: 'alarm',
  no_signer: 'normal',
  no_registry_identity: 'normal',
  key_derived_match: 'normal',
  key_derived_mismatch: 'alarm',
};

// CAPTURE_METHOD_VOCAB_SIGNALS, trust-signal.ts:912.
const CAPTURE_METHOD_VOCAB: Record<CaptureMethodVocabStatus, Tier> = {
  ok: 'verified',
  captureMethod_unknown: 'attention',
  producerProfile_bundle_unresolved: 'normal',
  no_capture_method: 'normal',
};

// CONTENT_PROFILE_SIGNALS, trust-signal.ts:946.
const CONTENT_PROFILE: Record<ContentProfileStatus, Tier> = {
  ok: 'verified',
  contentProfile_absent: 'normal',
  contentProfile_unknown: 'attention',
  contentProfile_inconsistent: 'attention',
};

/**
 * The copied tables under the site's own export names, for the test that
 * compares them with trust-signal.ts tier by tier.
 */
export const SITE_TABLES = {
  ENVELOPE_INTEGRITY_VERIFIED: ENVELOPE_INTEGRITY.verified,
  ENVELOPE_INTEGRITY_ALTERED: ENVELOPE_INTEGRITY.altered,
  ENVELOPE_INTEGRITY_CONTENT_PRIVATE: ENVELOPE_INTEGRITY['unavailable:private'],
  ENVELOPE_INTEGRITY_UNAVAILABLE: ENVELOPE_INTEGRITY['unavailable:unfetchable'],
  SIGNATURE_SIGNALS: SIGNATURE,
  CONTENT_CANONICALIZATION_SIGNALS: CONTENT_CANONICALIZATION,
  CONTENT_HASH_SIGNALS: CONTENT_HASH,
  KEY_TRUST_SIGNALS: KEY_TRUST,
  SIGNING_KEY_ID_SIGNALS: SIGNING_KEY_ID,
  BLOB_REF_REASON_SIGNALS: BLOB_REF_REASON,
  LIFECYCLE_ATTESTATION_NODE_ID_SIGNALS: LIFECYCLE_NODE_ID,
  LIFECYCLE_ATTESTATION_SIGNATURE_SIGNALS: LIFECYCLE_SIGNATURE,
  TYPE_RESOLUTION_SIGNALS: TYPE_RESOLUTION,
  SIGNER_IDENTITY_SIGNALS: SIGNER_IDENTITY,
  CAPTURE_METHOD_VOCAB_SIGNALS: CAPTURE_METHOD_VOCAB,
  CONTENT_PROFILE_SIGNALS: CONTENT_PROFILE,
} as const;

/** A carried lifecycle attestation, as `withdraw` prints it and `view` carries it. */
export interface CarriedNode {
  node: Record<string, unknown>;
  nodeId: string;
  signature?: { signature?: string; publicKey?: string; algorithm?: string } | null;
}

/** Every check's reading for one `verifyRecord` result and the lifecycle nodes the record carries. */
export function readingsOf(result: VerifyResult, carried: readonly CarriedNode[], packageHash: string): Reading[] {
  const out: Reading[] = [];
  const add = (check: string, field: string, status: string, tier: Tier) => out.push({ check, field, status, tier });

  const integrity = result.envelopeIntegrity;
  const integrityKey = integrity.status === 'unavailable' ? `unavailable:${integrity.reason ?? 'unfetchable'}` : integrity.status;
  add('#1', 'envelopeIntegrity', integrityKey, ENVELOPE_INTEGRITY[integrityKey as keyof typeof ENVELOPE_INTEGRITY]);
  add('#2', 'signatureValid', String(result.signatureValid), SIGNATURE[String(result.signatureValid) as keyof typeof SIGNATURE]);
  if (result.contentCanonicalization) {
    add('#3', 'contentCanonicalization', result.contentCanonicalization.status, CONTENT_CANONICALIZATION[result.contentCanonicalization.status]);
  }
  if (result.contentHash) add('#4', 'contentHash', result.contentHash.status, CONTENT_HASH[result.contentHash.status]);
  if (result.keyTrust) add('#5', 'keyTrust', result.keyTrust.status, KEY_TRUST[result.keyTrust.status]);
  if (result.signingKeyIdConsistency) {
    add('#6', 'signingKeyIdConsistency', result.signingKeyIdConsistency.status, SIGNING_KEY_ID[result.signingKeyIdConsistency.status]);
  }
  result.blobRefs.forEach((ref) => {
    const status = ref.ok ? 'ok' : (ref.reason ?? 'fetch_failed');
    add('#9', `blobRefs.${ref.field}`, status, ref.ok ? 'verified' : BLOB_REF_REASON[ref.reason ?? 'fetch_failed']);
  });
  carried.forEach((entry, i) => {
    const field = `lifecycleAttestations[${i}]`;
    if (entry.node['targetNodeId'] !== packageHash) {
      // verifyLifecycleChain leaves such a node out of this record's lifecycle.
      add('#10', `${field}.targetNodeId`, 'other_record', 'attention');
      return;
    }
    const verdict = verifyAttestationNode(entry.node, entry.nodeId, entry.signature ?? null);
    add('#10', `${field}.nodeId`, String(verdict.nodeIdMatches), LIFECYCLE_NODE_ID[String(verdict.nodeIdMatches) as 'true' | 'false']);
    add('#10', `${field}.signature`, String(verdict.signatureValid), LIFECYCLE_SIGNATURE[String(verdict.signatureValid) as keyof typeof SIGNATURE]);
  });
  if (result.typeResolution) add('#12', 'typeResolution', result.typeResolution.status, TYPE_RESOLUTION[result.typeResolution.status]);
  if (result.signerIdentity) add('#14', 'signerIdentity', result.signerIdentity.status, SIGNER_IDENTITY[result.signerIdentity.status]);
  if (result.captureMethodVocab) {
    add('#15', 'captureMethodVocab', result.captureMethodVocab.status, CAPTURE_METHOD_VOCAB[result.captureMethodVocab.status]);
  }
  if (result.contentProfile) add('#16', 'contentProfile', result.contentProfile.status, CONTENT_PROFILE[result.contentProfile.status]);
  return out;
}
