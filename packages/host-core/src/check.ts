// `check` (typedstandards#125): compare a fresh build with what is served, byte for
// byte, as the worked example's `check` does (package/build.mjs at b40c30f): every
// built file must be served unchanged, and no bundle, registry or index may be
// served that the build does not produce.

import { sameBytes, type FileMap } from './json.ts';
import { INDEX_PATH, REGISTRY_PATH, isHostPath } from './served.ts';

export interface CheckReport {
  ok: boolean;
  lines: string[];
}

/**
 * `built` is `buildHost(...).files`; `served` holds what the served directory has at
 * host-core's paths (bundles, the registry and the index). Other served files are
 * not host-core's and are not read.
 */
export function checkServed(built: FileMap, served: FileMap): CheckReport {
  const lines: string[] = [];
  let same = 0;
  for (const [path, bytes] of [...built].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const have = served.get(path);
    if (have === undefined) lines.push(`  FAIL  ${path}: not served`);
    else if (!sameBytes(have, bytes)) lines.push(`  FAIL  ${path}: differs from a fresh build`);
    else same += 1;
  }
  for (const path of [...served.keys()].filter(isHostPath).sort()) {
    if (built.has(path)) continue;
    const why =
      path === REGISTRY_PATH ? 'host.json serves no registry' : path === INDEX_PATH ? 'the build writes no index' : 'host.json lists no such record';
    lines.push(`  FAIL  ${path}: served, but ${why}`);
  }
  const ok = lines.length === 0;
  lines.push(ok ? `check: all ${built.size} served files equal a fresh build` : `check: FAILED; ${same} of ${built.size} built files are served unchanged`);
  return { ok, lines };
}
