// Offline verification of what a host serves (typedstandards#125). STUB: the typed
// surface lands first so the verify tests link.

import type { verifyRecord } from '@typedstandards/verify-core';
import type { FileMap } from './json.ts';

export interface VerifyTotals {
  records: number;
  ok: number;
  failed: number;
  active: number;
  withdrawn: number;
  superseded: number;
}

export interface VerifyReport {
  ok: boolean;
  /** What `typedstandards-host verify` prints, one entry per line. */
  lines: string[];
  totals: VerifyTotals;
  fetch: { global: number; injected: number };
}

export interface VerifyOptions {
  /** verify-core's `verifyRecord`, replaceable so a test can make a check fetch. */
  verifyRecord?: typeof verifyRecord;
}

/** Verify every record the served index lists, offline. */
export async function verifyServed(served: FileMap, options: VerifyOptions = {}): Promise<VerifyReport> {
  void served;
  void options;
  return { ok: false, lines: [], totals: { records: 0, ok: 0, failed: 0, active: 0, withdrawn: 0, superseded: 0 }, fetch: { global: 0, injected: 0 } };
}
