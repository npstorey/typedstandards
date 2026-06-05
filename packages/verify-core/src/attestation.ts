// Lifecycle attestation sub-type URIs (spec §8.10, §8.12.1) — browser-safe
// constants. The server `attestation.ts` builder (which mints nodes and so needs
// Node's `crypto.randomUUID`) re-exports these from verify-core, keeping a single
// definition of the URIs the verify side dispatches on. verify-core never builds
// nodes — it only verifies and orders them — so it carries the constants alone.

export const ATTESTATION_WITHDRAWS = 'attestation/withdraws/v1';
export const ATTESTATION_REINSTATES = 'attestation/reinstates/v1';

export type LifecycleAttestationType =
  | typeof ATTESTATION_WITHDRAWS
  | typeof ATTESTATION_REINSTATES;

/** The lifecycle sub-type URIs the verify side resolves (spec §8.12.1). */
export const LIFECYCLE_ATTESTATION_TYPES: readonly string[] = [
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
];
