// Check 8's inclusion verdict, bound to the record (spec §9.2 check #8) —
// browser-safe, offline.
//
// `verifyRekorInclusion` says whether a log entry is in a log the pinned key
// vouches for. A verdict about a record also needs the entry to be that record's:
// its body's `spec.data.hash` is `sha512` with the value
// `rekorHashForPackage(packageHash)`, the comparison `verifyRekorEntry` makes for
// hash parity. Both sources of a verdict read it here: the entry body and proof an
// input carries (`verifyRecord`) and an entry `verifyRekorEntry` fetches.
//
// Internal: `index.ts` does not re-export this module.

import { base64ToBytes } from './primitives.ts';
import { rekorHashForPackage } from './signature.ts';
import {
  verifyRekorInclusion,
  type RekorInclusionProof,
  type RekorInclusionResult,
} from './rekor-inclusion.ts';

/** Whether a log entry body records `packageHash`: `spec.data.hash` is `sha512`
 *  with the value `rekorHashForPackage(packageHash)`. An empty hash, or a body that
 *  does not decode, records nothing. */
export function entryRecordsPackage(entryBody: string | Uint8Array, packageHash: string): boolean {
  if (!packageHash) return false;
  try {
    const bytes = typeof entryBody === 'string' ? base64ToBytes(entryBody) : entryBody;
    const body: unknown = JSON.parse(new TextDecoder().decode(bytes));
    const hash = (body as { spec?: { data?: { hash?: { algorithm?: unknown; value?: unknown } } } } | null)
      ?.spec?.data?.hash;
    return hash?.algorithm === 'sha512' && hash.value === rekorHashForPackage(packageHash);
  } catch {
    return false;
  }
}

/**
 * Check 8's inclusion verdict for a record. An entry that does not record
 * `packageHash` reads `inclusionVerified: false` and `checkpointVerified: false`,
 * with the proof's `treeSize` and `leafIndex` and no `reason` (the proof is not
 * evaluated). Otherwise the verdict is `verifyRekorInclusion`'s.
 */
export function verifyRekorInclusionForRecord(
  entryBody: string | Uint8Array,
  inclusionProof: RekorInclusionProof,
  packageHash: string,
): RekorInclusionResult {
  if (!entryRecordsPackage(entryBody, packageHash)) {
    return {
      inclusionVerified: false,
      checkpointVerified: false,
      treeSize: inclusionProof.treeSize,
      leafIndex: inclusionProof.logIndex,
    };
  }
  return verifyRekorInclusion(entryBody, inclusionProof);
}
