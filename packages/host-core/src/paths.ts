// `/`-separated path arithmetic for the in-memory file maps (typedstandards#125).
// No Node `path`: shipped source is browser-safe, so the few operations the host
// stages need are written out here.

/** Resolve `.` and `..` segments and repeated separators. A leading `/` is kept. */
export function normalizePath(path: string): string {
  const absolute = path.startsWith('/');
  const out: string[] = [];
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') out.pop();
      else if (!absolute) out.push('..');
      continue;
    }
    out.push(segment);
  }
  const joined = out.join('/');
  return absolute ? `/${joined}` : joined || '.';
}

/** Join path segments, then normalize. A later absolute segment restarts the path. */
export function joinPath(...parts: string[]): string {
  let path = '';
  for (const part of parts) {
    if (part === '') continue;
    path = part.startsWith('/') || path === '' ? part : `${path}/${part}`;
  }
  return normalizePath(path || '.');
}

/** The directory part of a path: `.` for a bare file name. */
export function dirnameOf(path: string): string {
  const normal = normalizePath(path);
  const at = normal.lastIndexOf('/');
  if (at === -1) return '.';
  return at === 0 ? '/' : normal.slice(0, at);
}

/** Whether `path` is `dir` itself or lies under it. Both are normalized first. */
export function isWithin(path: string, dir: string): boolean {
  const p = normalizePath(path);
  const d = normalizePath(dir);
  if (d === '.') return !p.startsWith('/') && !p.startsWith('..');
  return p === d || p.startsWith(d === '/' ? '/' : `${d}/`);
}

const NAME_SEGMENT = /^[A-Za-z0-9._-]+$/;

/**
 * A record name is one or more `/`-separated segments of letters, digits, `.`,
 * `_` and `-`, with no `.` or `..` segment: it becomes a served path,
 * `bundles/<name>.bundle.json`, so it may not climb out of `bundles/`.
 */
export function isRecordName(name: string): boolean {
  return name.split('/').every((s) => NAME_SEGMENT.test(s) && s !== '.' && s !== '..');
}
