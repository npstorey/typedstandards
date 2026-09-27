// Attestation sub-type URIs (spec §8.10, §8.12.1) — browser-safe constants. The
// server `attestation.ts` builder (which mints nodes and so needs Node's
// `crypto.randomUUID`) re-exports these from verify-core, keeping a single
// definition of the URIs the verify side dispatches on. verify-core never builds
// nodes — it only verifies and orders them — so it carries the constants alone.

export const ATTESTATION_WITHDRAWS = 'attestation/withdraws/v1';
export const ATTESTATION_REINSTATES = 'attestation/reinstates/v1';
export const ATTESTATION_SUPERSEDES = 'attestation/supersedes/v1';
export const ATTESTATION_REVISES = 'attestation/revises/v1';
export const ATTESTATION_CORROBORATES = 'attestation/corroborates/v1';
export const ATTESTATION_CONTRADICTS = 'attestation/contradicts/v1';

/** The withdrawal/reinstatement pair: the two lifecycle sub-types the legacy
 *  `withdrawnAt` / `reinstatedAt` columns also record (spec §8.10.4). produce-core's
 *  `EmittableAttestationType` includes this union beside the other sub-types it
 *  emits, `supersedes` and `revises` among them, so it is not the set produce-core
 *  emits. No verify-core check reads it: the lifecycle reads
 *  `LIFECYCLE_STATUS_ATTESTATION_TYPES` and `LIFECYCLE_CHAIN_ATTESTATION_TYPES`. */
export type LifecycleAttestationType =
  | typeof ATTESTATION_WITHDRAWS
  | typeof ATTESTATION_REINSTATES;

/** The values of `LifecycleAttestationType`, the withdrawal/reinstatement pair. Not
 *  the set produce-core emits, and not read by any verify-core check (see
 *  `LifecycleAttestationType`). */
export const LIFECYCLE_ATTESTATION_TYPES: readonly string[] = [
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
];

/** The sub-types that move a record's lifecycle status (spec §8.10.6: `active`,
 *  `withdrawn`, `superseded`). `revises` and `publishes` never do. */
export const LIFECYCLE_STATUS_ATTESTATION_TYPES: readonly string[] = [
  ATTESTATION_WITHDRAWS,
  ATTESTATION_REINSTATES,
  ATTESTATION_SUPERSEDES,
];

/** The publisher-only lifecycle sub-types surfaced in a record's lifecycle chain:
 *  the status-moving three, and `revises`, which is shown but moves nothing. */
export const LIFECYCLE_CHAIN_ATTESTATION_TYPES: readonly string[] = [
  ...LIFECYCLE_STATUS_ATTESTATION_TYPES,
  ATTESTATION_REVISES,
];
