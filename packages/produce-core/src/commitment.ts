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
// Every value is caller-supplied, and two are REQUIRED — absent is an error,
// never a default — because this view is what a third party resolves while
// verifying, so a value the core invents here is asserted to that reader as
// one the producer set (civic-ai-tools ADR-0024). `trustRegistryUrl` is
// per-publisher CONFIGURATION, never a constant, so a prospective adopter's
// registry travels with its proofs; `visibility` is the disclosure state,
// which the spec makes required and gives no default, and which defaulted
// would state a disclosure claim nobody made.
//
// `trustRegistryUrl` has one conditional case (hub ADR-0030 §6): a
// self-certifying signer — a key-derived `signer.identifier` (`did:key:`) at
// `bindingTier: "pseudonymous"` — has no domain and so no registry. Its view
// omits the key. The builder then checks the claim it is asked to serve: it
// derives the identifier from `signature.publicKey` and throws when that is
// not `signer.identifier`, since such a view fails check #14 on every
// verifier. Every other case keeps the ADR-0024 throw.
//
// The signature envelope is carried verbatim (including `algorithm` and
// `kid`): `algorithm` is load-bearing for the verifier's Ed25519/Ed25519ph
// dispatch, and `kid` is the trust-registry lookup handle; both may be absent
// on packages signed via an older path and are carried as-is.
//
// Mapping storage rows / records onto this input is implementation-side
// adapter work; the core defines the shape and the conditional-emission rules
// (absent proofs are omitted, never emitted as null).

import {
  deriveKeyDerivedIdentifier,
  isKeyDerivedIdentifier,
  type CarriedLifecycleNode,
  type SignerIdentity,
} from '@typedstandards/verify-core';

// The schema version this view is published against, emitted as §8.8.1's
// `protocolVersion`. The wire key was `evidenceProtocolVersion` before the
// 2026-08-19 vocabulary settlement (spec Appendix J, migration class
// `frozen-in-signed-artifacts`): already-signed views keep the old key
// forever — rewriting it would change the envelope hash — and a conformant
// verifier MUST accept both keys. New emissions mint the new key only; this
// constant carries the value, unchanged, under either.
const PROTOCOL_VERSION = '0.1.0';

// The one `bindingTier` at which a key-derived signer may omit
// `trustRegistryUrl` (hub ADR-0030 §3, §6).
const SELF_CERTIFYING_TIER = 'pseudonymous';

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
   *  not be disclosed for sealed-visibility records). */
  packageUrl?: string;
  /** REQUIRED disclosure state (spec §8.8.1) — what lets a verifier render a
   *  sealed / not-publicly-located state honestly instead of treating a
   *  missing packageUrl as an error. Caller-supplied, never defaulted: the
   *  spec defines no default, and a default here would assert a disclosure
   *  state nobody set inside the artifact a verifier resolves.
   *
   *  Optional in the TYPE only — absence is a runtime error today, and a
   *  future minor makes the field required in the type as well.
   *
   *  The vocabulary of record is `sealed` / `public`. The core carries
   *  whatever string it is given VERBATIM and normalizes nothing; mapping the
   *  pre-ADR-0016 spellings (`committed` / `published`, which remain
   *  permanently accepted inputs) onto the vocabulary of record is
   *  implementation-side adapter work, like every other row-to-view mapping
   *  here. */
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
   *  publisher's public keys resolve. Never a constant in the core.
   *
   *  Optional in the TYPE for one case only (hub ADR-0030 §6): a
   *  self-certifying signer — `signer.identifier` key-derived (`did:key:`) and
   *  `signer.bindingTier` `pseudonymous` — whose identifier equals the one
   *  derived from `signature.publicKey`. The view then omits the key (never
   *  `null`). Absent in any other case is a runtime error. */
  trustRegistryUrl?: string;
  /** Optional secondary registry path served byte-identical to the canonical
   *  one, for clients that only know an older path. */
  trustRegistryUrlLegacy?: string;
  /** Content-derived display strings — redacted for sealed records. Pass
   *  `null` to emit an explicit JSON null. */
  subjectTitle?: string | null;
  subjectSummary?: string | null;
  /** Sealed-record redaction: the commitment is public by design (the
   *  hash is already on the transparency log), but the content's location and
   *  content-derived strings are not. When set, the view omits `packageUrl`,
   *  `subjectTitle`, and `subjectSummary`; proof-side fields are served
   *  unredacted — they ARE the commitment. */
  redactContentSurface?: boolean;
}

/**
 * A self-certifying view with no `trustRegistryUrl` must carry the key its
 * signer's identifier names: derive the identifier from the verbatim
 * `signature.publicKey` (verify-core's derivation, the one check #14 runs)
 * and throw unless it equals `signer.identifier`. No key material is needed:
 * the public key is already in the view.
 */
function assertKeyDerivedIdentifierMatches(
  claimed: string,
  signature: Record<string, unknown> | null | undefined,
): void {
  const publicKey = signature?.['publicKey'];
  if (typeof publicKey !== 'string' || publicKey === '') {
    throw new Error(
      'buildCommitmentView: a self-certifying signer with no trustRegistryUrl requires signature.publicKey — the key-derived identifier is checked against the key the view carries',
    );
  }
  let derived: string;
  try {
    derived = deriveKeyDerivedIdentifier(publicKey);
  } catch (err) {
    throw new Error(
      `buildCommitmentView: signature.publicKey is not an Ed25519 SPKI key, so the key-derived signer identifier cannot be checked (${(err as Error).message})`,
    );
  }
  if (derived !== claimed) {
    throw new Error(
      `buildCommitmentView: signer.identifier ${claimed} is not the identifier derived from signature.publicKey (${derived}) — the view would fail check #14 on every verifier`,
    );
  }
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
  // One rule, two fields: nothing this view asserts to a verifier may be
  // supplied by the core on the caller's behalf (civic-ai-tools ADR-0024).
  if (!input.trustRegistryUrl) {
    // The one exception (hub ADR-0030 §6): a self-certifying signer. Keyed on
    // the identifier AND the tier: no signer, an identifier that is not
    // key-derived, or any other tier keeps the ADR-0024 throw.
    const signer = input.signer;
    if (
      !signer ||
      !isKeyDerivedIdentifier(signer.identifier) ||
      signer.bindingTier !== SELF_CERTIFYING_TIER
    ) {
      throw new Error(
        'buildCommitmentView requires trustRegistryUrl — per-publisher configuration is caller-supplied, never a core constant',
      );
    }
    assertKeyDerivedIdentifierMatches(signer.identifier, input.signature);
  }
  if (!input.visibility) {
    throw new Error(
      'buildCommitmentView requires visibility — the disclosure state is caller-supplied, never defaulted: a default asserts a state nobody set inside the view a verifier resolves',
    );
  }
  const redact = input.redactContentSurface === true;

  return {
    protocolVersion: PROTOCOL_VERSION,
    packageHash: input.packageHash,
    // The content's location is never emitted on a redacted view.
    ...(redact || input.packageUrl === undefined
      ? {}
      : { packageUrl: input.packageUrl }),
    visibility: input.visibility,
    captureMethod: input.captureMethod ?? null,
    // Spec §8.8.1 defines `"default"` for a package that carries no content
    // profile: an honest not-applicable, not an assertion about the record —
    // so this default stays where the visibility one could not (ADR-0024 §B).
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
    // Omitted (never null) only for a self-certifying signer — checked above.
    ...(input.trustRegistryUrl ? { trustRegistryUrl: input.trustRegistryUrl } : {}),
    ...(input.trustRegistryUrlLegacy
      ? { trustRegistryUrlLegacy: input.trustRegistryUrlLegacy }
      : {}),
    // Content-derived strings — redacted for sealed records.
    ...(redact
      ? {}
      : { subjectTitle: input.subjectTitle, subjectSummary: input.subjectSummary }),
  };
}
