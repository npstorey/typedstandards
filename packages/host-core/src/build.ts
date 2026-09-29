// The host build (typedstandards#125 G0 D1, D2, D6, D12). STUB: the typed surface
// lands first so the oracle test links; the build follows in its own commit.

import type { FileMap } from './json.ts';
import type { HostIndex } from './served.ts';

export interface RegistryDocument {
  $comment?: string;
  keys: Array<Record<string, unknown>>;
}

export interface HostBuild {
  /** Served path (relative to the served directory) to bytes. */
  files: Map<string, Uint8Array>;
  index: HostIndex;
  registry: RegistryDocument | null;
}

/**
 * Build what a host serves from a parsed `host.json` and the files it names, keyed
 * by their paths relative to the manifest.
 */
export function buildHost(manifest: unknown, files: FileMap): HostBuild {
  void manifest;
  void files;
  return { files: new Map(), index: { version: 1, host: '', records: [] }, registry: null };
}
