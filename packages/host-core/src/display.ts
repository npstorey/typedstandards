// The display seam (typedstandards#125 G0 D5). STUB: the typed surface lands first
// so the display tests link.

import type { JsonObject } from './json.ts';
import type { IndexRecord } from './served.ts';

export type ExtensionValue = string | number | boolean | null;

export interface DisplayRule {
  status: string[];
  signer?: string[];
  type?: string[];
  extensions?: Record<string, ExtensionValue[]>;
  as: string;
}

export interface DisplayPolicy {
  signer?: string[];
  type?: string[];
  display: DisplayRule[];
  unmatched: 'refuse';
}

export interface Display {
  /** The matching rule's `as`. */
  as: string;
  /** The matching rule's position in `display`. */
  rule: number;
}

/** The record fields the seam reads: an index v1 record has them all. */
export type DisplayRecord = Pick<IndexRecord, 'signer' | 'type'> & { status: string; name?: string; extensions?: JsonObject };

export function parsePolicy(value: unknown): DisplayPolicy {
  return value as DisplayPolicy;
}

export function displayOf(record: DisplayRecord, policy: DisplayPolicy): Display {
  void record;
  void policy;
  return { as: '', rule: -1 };
}
