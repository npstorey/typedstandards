// The host manifest, `host.json` (typedstandards#125 G0 D12): what a host serves and
// how. Every path in it is relative to the manifest's own directory.
//
//   { origin, visibility, registry: {$comment?} | null, index: {$comment?},
//     records: [{ name, signed, attestations[], title, extensions? }] }
//
// `visibility` is host-wide in 0.1.0 and is never defaulted: produce-core refuses a
// view without one. `registry: null` serves no key registry, which produce-core
// accepts only for a key-derived did:key signer at bindingTier "pseudonymous".

import { HostError, isObject, type JsonObject } from './json.ts';
import { isRecordName } from './paths.ts';

export interface HostManifestRecord {
  /** The served name: the bundle is served at `bundles/<name>.bundle.json`. */
  name: string;
  /** What the CLI's `sign` printed, `{package, envelopeHash, signature}`. */
  signed: string;
  /** What the CLI's `withdraw` or `attest` printed, `{node, nodeId, signature}`, one file each. */
  attestations: string[];
  /** The view's `subjectTitle`, which the host supplies. */
  title: string;
  /** Host-specific fields, copied into the index record as its `extensions`. */
  extensions?: JsonObject;
}

export interface HostManifest {
  /** The host's origin, `https://…`, with no trailing `/`; a path prefix is allowed. */
  origin: string;
  /** The views' disclosure state, host-wide. */
  visibility: string;
  /** Serve a key registry at `.well-known/typed-publisher.json`, or `null` for none. */
  registry: { $comment?: string } | null;
  /** The served index's own fields. */
  index: { $comment?: string };
  records: HostManifestRecord[];
}

const ORIGIN = /^https:\/\/[^/?#\s]+(\/[^?#\s]*[^/?#\s])?$/;

function exactKeys(value: JsonObject, allowed: readonly string[], required: readonly string[], where: string): void {
  const extra = Object.keys(value).filter((k) => !allowed.includes(k));
  if (extra.length) throw new HostError(`${where}: ${extra.join(', ')}: not a field host.json defines`);
  const missing = required.filter((k) => !(k in value));
  if (missing.length) throw new HostError(`${where} is missing ${missing.join(', ')}`);
}

function comment(value: JsonObject, where: string): { $comment?: string } {
  exactKeys(value, ['$comment'], [], where);
  if ('$comment' in value && typeof value['$comment'] !== 'string') throw new HostError(`${where}.$comment must be a string`);
  return typeof value['$comment'] === 'string' ? { $comment: value['$comment'] } : {};
}

const relativePath = (v: unknown): v is string => typeof v === 'string' && v !== '' && !v.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(v);

/** Validate a parsed `host.json`. Refuses anything it does not define. */
export function parseManifest(value: unknown, where = 'host.json'): HostManifest {
  if (!isObject(value)) throw new HostError(`${where} must be a JSON object`);
  exactKeys(value, ['$comment', 'origin', 'visibility', 'registry', 'index', 'records'], ['origin', 'registry', 'index', 'records'], where);
  const { origin, visibility, registry, index, records } = value;
  if (typeof origin !== 'string' || !ORIGIN.test(origin)) {
    throw new HostError(`${where}: origin must be an https:// origin with no trailing /, query or fragment (a path prefix is allowed)`);
  }
  if (typeof visibility !== 'string' || visibility === '') {
    throw new HostError(`${where}: visibility is required (for example "public"); a view states its disclosure state and it is never defaulted`);
  }
  if (registry !== null && !isObject(registry)) throw new HostError(`${where}: registry must be an object ({"$comment": …} or {}) or null`);
  if (!isObject(index)) throw new HostError(`${where}: index must be an object ({"$comment": …} or {})`);
  if (!Array.isArray(records) || records.length === 0) throw new HostError(`${where}: records must be a non-empty array`);
  const seen = new Set<string>();
  const parsed = records.map((r, i): HostManifestRecord => {
    const at = `${where}: records[${i}]`;
    if (!isObject(r)) throw new HostError(`${at} must be an object`);
    exactKeys(r, ['$comment', 'name', 'signed', 'attestations', 'title', 'extensions'], ['name', 'signed', 'attestations', 'title'], at);
    const { name, signed, attestations, title, extensions } = r;
    if (typeof name !== 'string' || !isRecordName(name)) {
      throw new HostError(`${at}.name must be /-separated segments of letters, digits, ".", "_" and "-", with no "." or ".." segment`);
    }
    if (seen.has(name)) throw new HostError(`${at}.name: ${name} is listed twice`);
    seen.add(name);
    if (!relativePath(signed)) throw new HostError(`${at}.signed must be a path relative to host.json`);
    if (!Array.isArray(attestations) || !attestations.every(relativePath)) {
      throw new HostError(`${at}.attestations must be an array of paths relative to host.json ([] for none)`);
    }
    if (typeof title !== 'string' || title === '') throw new HostError(`${at}.title must be a non-empty string`);
    if (extensions !== undefined && !isObject(extensions)) throw new HostError(`${at}.extensions must be an object`);
    return { name, signed, attestations: [...attestations], title, ...(extensions !== undefined ? { extensions } : {}) };
  });
  return {
    origin,
    visibility,
    registry: registry === null ? null : comment(registry, `${where}: registry`),
    index: comment(index, `${where}: index`),
    records: parsed,
  };
}
