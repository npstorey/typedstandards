// What a host serves, and where (typedstandards#125 G0 D6). Paths are relative to
// the served directory:
//
//   bundles/<name>.bundle.json          one bundle per record: the view plus the package
//   .well-known/typed-publisher.json    the key registry, when the manifest serves one
//   records.json                        the index, version 1
//
// Index v1: { version: 1, $comment?, host, trustRegistryUrl?, records[] }, each record
// { name, bundle, packageHash, createdAt, type, signer, status,
//   withdrawn?{at, reason}, superseded?{at, successorNodeId}, extensions? },
// in the manifest's order. `status`, `withdrawn` and `superseded` are verify-core's
// verifyLifecycleChain reading of the attestations each bundle carries. `type` is
// verify-core's resolvePackageType reading of the package: a package with no type is
// listed as content/analysis/v1 (spec §8.8.1). build never writes an index this
// module's parseIndex refuses.

import { LIFECYCLE_STATUSES, type LifecycleStatus } from '@typedstandards/verify-core';
import { HostError, isObject, type JsonObject } from './json.ts';

export const INDEX_PATH = 'records.json';
export const REGISTRY_PATH = '.well-known/typed-publisher.json';
export const BUNDLES_DIR = 'bundles';

export const bundlePathOf = (name: string): string => `${BUNDLES_DIR}/${name}.bundle.json`;

/** Whether host-core writes (and so `check` reads) this served path. */
export const isHostPath = (path: string): boolean =>
  path === INDEX_PATH || path === REGISTRY_PATH || (path.startsWith(`${BUNDLES_DIR}/`) && path.endsWith('.bundle.json'));

export interface IndexRecord {
  name: string;
  /** A path relative to the served directory, or an absolute URL. */
  bundle: string;
  packageHash: string;
  createdAt: string;
  type: string;
  signer: string;
  status: LifecycleStatus;
  withdrawn?: { at: string; reason?: string };
  superseded?: { at: string; successorNodeId: string };
  extensions?: JsonObject;
}

export interface HostIndex {
  version: 1;
  $comment?: string;
  /** The origin plus `/`: a relative `bundle` is served at `host + bundle`. */
  host: string;
  trustRegistryUrl?: string;
  records: IndexRecord[];
}

const str = (v: unknown): v is string => typeof v === 'string' && v !== '';

/** Validate a parsed index v1 document. */
export function parseIndex(value: unknown, where = INDEX_PATH): HostIndex {
  if (!isObject(value)) throw new HostError(`${where} must be a JSON object`);
  if (value['version'] !== 1) throw new HostError(`${where}: version must be 1 (this is index v1)`);
  if (!str(value['host']) || !value['host'].endsWith('/')) throw new HostError(`${where}: host must be the origin plus /`);
  if ('trustRegistryUrl' in value && !str(value['trustRegistryUrl'])) throw new HostError(`${where}: trustRegistryUrl must be a string`);
  if ('$comment' in value && typeof value['$comment'] !== 'string') throw new HostError(`${where}: $comment must be a string`);
  const records = value['records'];
  if (!Array.isArray(records)) throw new HostError(`${where}: records must be an array`);
  records.forEach((r, i) => {
    const at = `${where}: records[${i}]`;
    if (!isObject(r)) throw new HostError(`${at} must be an object`);
    for (const k of ['name', 'bundle', 'packageHash', 'createdAt', 'type', 'signer', 'status']) {
      if (!str(r[k])) throw new HostError(`${at}.${k} must be a non-empty string`);
    }
    if (!(LIFECYCLE_STATUSES as readonly string[]).includes(r['status'] as string)) {
      throw new HostError(`${at}.status ${String(r['status'])} is not one of verify-core's LIFECYCLE_STATUSES (${LIFECYCLE_STATUSES.join(', ')})`);
    }
    if ('extensions' in r && !isObject(r['extensions'])) throw new HostError(`${at}.extensions must be an object`);
  });
  return value as unknown as HostIndex;
}
