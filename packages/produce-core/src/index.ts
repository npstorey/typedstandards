// @typedstandards/produce-core — the format-neutral, I/O-free producer core
// for Typed Standards evidence packages: envelope + attestation assembly
// (spec §8.1, §8.12), the Ed25519ph signing mechanism (§8.3.1), pure
// external-proof codecs (RFC 3161 / Rekor hashedrekord), the §8.8.1
// commitment view, and generic PROV-O helpers (§8.9). The verification
// counterpart is @typedstandards/verify-core — the ONLY runtime dependency,
// which is load-bearing: producer and verifier share one canonicalization /
// hash implementation by construction.
//
// Discipline (mirrors verify-core, enforced by the ESLint purity config and
// `browser-safety.test.ts`): pure functions over provided data — no `node:*`
// imports, no environment reads, no network I/O, no clock, no RNG.
// Determinism inputs (`packageId`, `createdAt`, `signingKeyId`) and
// configuration (signing key, kid, `trustRegistryUrl`) are caller-supplied.
// Not signing is a first-class result: a built envelope + envelope hash with
// no signature — nothing here labels an unsigned result as anything else.

export * from './envelope.ts';
export * from './attestation.ts';
export * from './signing.ts';
export * from './rfc3161-request.ts';
export * from './rekor-proposal.ts';
export * from './commitment.ts';
export * from './provenance.ts';

// Shared shapes and the canonicalization chain, re-exported from the
// verification core so a producer needs a single import.
export type {
  BlobRef,
  CarriedLifecycleNode,
  SignerIdentity,
} from '@typedstandards/verify-core';
export {
  LEGACY_JSON_CANONICALIZATION,
  computeContentHashSha256,
  computeEnvelopeHash,
} from '@typedstandards/verify-core';
