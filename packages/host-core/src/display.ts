// The display seam (typedstandards#125 G0 D5, D9): `displayOf(record, policy)` says
// how a host shows a record it serves, by the host's own policy. The policy is not
// signed and nothing verifies it; it only decides what a page shows.
//
// A policy is JSON, with `$comment` strings allowed anywhere:
//
//   { signer?, type?, display: [{ status, signer?, type?, extensions?, as }], unmatched: "refuse" }
//
// `signer`, `type` and `status` are a string or a list of strings; `extensions`
// maps an index `extensions` key (a host's roles, say) to the values it admits.
// A record is displayed by the first rule it matches. It is refused when:
//   - its status is not one of verify-core's LIFECYCLE_STATUSES;
//   - the policy's top-level signer or type does not name it;
//   - no rule matches (`unmatched: refuse`, the only mode in 0.1.0).
// Every rule names its statuses, so `superseded` is displayed only when a rule
// names it.
//
// The generic part of the worked example's docs/host-policy.yaml (b40c30f):
// its roles become an `extensions` key; its map, rings and fill stay with its site.

import { LIFECYCLE_STATUSES } from '@typedstandards/verify-core';
import { HostError, isObject, type JsonObject } from './json.ts';
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

const STATUSES: readonly string[] = LIFECYCLE_STATUSES;

function keysOnly(value: JsonObject, allowed: readonly string[], where: string): void {
  const extra = Object.keys(value).filter((k) => k !== '$comment' && !allowed.includes(k));
  if (extra.length) throw new HostError(`${where}: ${extra.join(', ')}: not a field a display policy defines`);
  if ('$comment' in value && typeof value['$comment'] !== 'string') throw new HostError(`${where}.$comment must be a string`);
}

function strings(value: unknown, where: string): string[] {
  const list = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(list) || list.length === 0 || !list.every((s) => typeof s === 'string' && s !== '')) {
    throw new HostError(`${where} must be a non-empty string or a non-empty list of them`);
  }
  return list as string[];
}

function statuses(value: unknown, where: string): string[] {
  if (value === undefined) throw new HostError(`${where} is required: a rule names the statuses it displays`);
  const list = strings(value, where);
  for (const s of list) {
    if (!STATUSES.includes(s)) throw new HostError(`${where}: ${s} is not one of verify-core's LIFECYCLE_STATUSES (${STATUSES.join(', ')})`);
  }
  return list;
}

const scalar = (v: unknown): v is ExtensionValue => v === null || ['string', 'number', 'boolean'].includes(typeof v);

/** Validate a parsed display policy. */
export function parsePolicy(value: unknown, where = 'policy'): DisplayPolicy {
  if (!isObject(value)) throw new HostError(`${where} must be a JSON object`);
  keysOnly(value, ['signer', 'type', 'display', 'unmatched'], where);
  if (value['unmatched'] !== 'refuse') throw new HostError(`${where}: unmatched must be "refuse", the only mode in 0.1.0`);
  const display = value['display'];
  if (!Array.isArray(display) || display.length === 0) throw new HostError(`${where}: display must be a non-empty list of rules`);
  const rules = display.map((rule, i): DisplayRule => {
    const at = `${where}: display[${i}]`;
    if (!isObject(rule)) throw new HostError(`${at} must be an object`);
    keysOnly(rule, ['status', 'signer', 'type', 'extensions', 'as'], at);
    if (typeof rule['as'] !== 'string' || rule['as'] === '') throw new HostError(`${at}.as must be a non-empty string`);
    let extensions: Record<string, ExtensionValue[]> | undefined;
    if (rule['extensions'] !== undefined) {
      if (!isObject(rule['extensions'])) throw new HostError(`${at}.extensions must be an object`);
      extensions = {};
      for (const [key, admitted] of Object.entries(rule['extensions'])) {
        if (!Array.isArray(admitted) || admitted.length === 0 || !admitted.every(scalar)) {
          throw new HostError(`${at}.extensions.${key} must be a non-empty list of strings, numbers, booleans or null`);
        }
        extensions[key] = admitted;
      }
    }
    return {
      status: statuses(rule['status'], `${at}.status`),
      ...(rule['signer'] !== undefined ? { signer: strings(rule['signer'], `${at}.signer`) } : {}),
      ...(rule['type'] !== undefined ? { type: strings(rule['type'], `${at}.type`) } : {}),
      ...(extensions ? { extensions } : {}),
      as: rule['as'],
    };
  });
  return {
    ...(value['signer'] !== undefined ? { signer: strings(value['signer'], `${where}.signer`) } : {}),
    ...(value['type'] !== undefined ? { type: strings(value['type'], `${where}.type`) } : {}),
    display: rules,
    unmatched: 'refuse',
  };
}

function matches(rule: DisplayRule, record: DisplayRecord): boolean {
  if (!rule.status.includes(record.status)) return false;
  if (rule.signer && !rule.signer.includes(record.signer)) return false;
  if (rule.type && !rule.type.includes(record.type)) return false;
  for (const [key, admitted] of Object.entries(rule.extensions ?? {})) {
    const ext = record.extensions;
    if (!ext || !Object.hasOwn(ext, key) || !admitted.includes(ext[key] as ExtensionValue)) return false;
  }
  return true;
}

/**
 * How the policy displays a record: the first rule it matches. Throws `HostError`
 * (a refusal) for a status outside LIFECYCLE_STATUSES and for a record no rule
 * matches.
 */
export function displayOf(record: DisplayRecord, policy: DisplayPolicy): Display {
  const label = record.name ?? 'the record';
  if (!STATUSES.includes(record.status)) {
    throw new HostError(`${label}: status ${record.status} is not one of verify-core's LIFECYCLE_STATUSES (${STATUSES.join(', ')}); refused`);
  }
  const named = (!policy.signer || policy.signer.includes(record.signer)) && (!policy.type || policy.type.includes(record.type));
  const rule = named ? policy.display.findIndex((r) => matches(r, record)) : -1;
  if (rule === -1) {
    throw new HostError(`no rule displays ${label} (status ${record.status}, signer ${record.signer}, type ${record.type}); unmatched: refuse`);
  }
  return { as: policy.display[rule].as, rule };
}
