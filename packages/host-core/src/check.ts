// Compare a fresh build with what is served (typedstandards#125). STUB: the typed
// surface lands first.

import type { FileMap } from './json.ts';

export interface CheckReport {
  ok: boolean;
  lines: string[];
}

export function checkServed(built: FileMap, served: FileMap): CheckReport {
  void built;
  void served;
  return { ok: false, lines: [] };
}
