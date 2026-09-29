// The `typedstandards-host` command logic (typedstandards#125 G0 D3 + D11), I/O-free.
// The Node entry, node/main.ts, imports this as `#cli` and supplies the `Io`. It is
// not part of the library's exports.

import { buildHost } from './build.ts';
import { checkServed } from './check.ts';
import type { Io, ParseArgs } from './io.ts';
import { HostError, parseJsonFile, serialize, type FileMap } from './json.ts';
import { linksFor, type BadgeTheme } from './links.ts';
import { parseManifest } from './manifest.ts';
import { dirnameOf, isWithin, joinPath } from './paths.ts';
import { BUNDLES_DIR, INDEX_PATH, REGISTRY_PATH, parseIndex } from './served.ts';
import { verifyServed } from './verify.ts';

export type { Io, ParseArgs };

export const EXIT = {
  ok: 0,
  /** `check` found a difference, or `verify` a record that does not verify. */
  failed: 1,
  /** An argument or an input file is wrong. */
  usage: 2,
  /** Anything else: a bug in host-core. */
  internal: 4,
} as const;

export const USAGE = `Usage: typedstandards-host <command> [--manifest <file>] [--out <dir>]

  build   Build the bundles, the key registry and records.json from the host
          manifest and the signed files it names, and write them to --out.
  check   Build in memory and compare with --out byte for byte: every built file
          must be served unchanged, and no other bundle, registry or index served.
  verify  Verify every record --out's records.json lists, offline, with
          @typedstandards/verify-core; the network is blocked and fetches counted.
  links   Print each served record's verifier link and HTML and Markdown badge
          snippets, as JSON. [--theme light|dark]

--manifest defaults to host.json. --out, the served directory, defaults to docs/
beside the manifest; build refuses a manifest or input file inside it. verify and
links read --out only.

Exit codes: 0 ok, 1 check or verification failed, 2 usage or input error,
4 internal error.
`;

const OPTIONS = {
  manifest: { type: 'string' },
  out: { type: 'string' },
  theme: { type: 'string' },
} as const;

interface Values {
  manifest?: string;
  out?: string;
  theme?: string;
}

interface Paths {
  manifest: string;
  manifestDir: string;
  out: string;
}

function pathsOf(values: Values, io: Io): Paths {
  const manifest = io.resolve(values.manifest ?? 'host.json');
  const manifestDir = dirnameOf(manifest);
  const out = values.out !== undefined ? io.resolve(values.out) : joinPath(manifestDir, 'docs');
  return { manifest, manifestDir, out };
}

function readManifestAndInputs(paths: Paths, io: Io): { manifest: unknown; files: Map<string, Uint8Array> } {
  if (isWithin(paths.manifest, paths.out)) throw new HostError(`the manifest ${paths.manifest} is inside the served directory ${paths.out}; keep inputs out of what is served`);
  if (!io.exists(paths.manifest)) throw new HostError(`${paths.manifest} was not found`);
  const manifest = parseJsonFile(io.readFile(paths.manifest), paths.manifest);
  const parsed = parseManifest(manifest, paths.manifest);
  const files = new Map<string, Uint8Array>();
  for (const rel of parsed.records.flatMap((r) => [r.signed, ...r.attestations])) {
    const full = joinPath(paths.manifestDir, rel);
    if (isWithin(full, paths.out)) throw new HostError(`${rel} is inside the served directory ${paths.out}; keep inputs out of what is served`);
    if (!io.exists(full)) throw new HostError(`${rel}, which ${paths.manifest} names, was not found`);
    files.set(rel, io.readFile(full));
  }
  return { manifest, files };
}

/** What the served directory holds at host-core's paths. */
function readServed(out: string, io: Io): FileMap {
  const served = new Map<string, Uint8Array>();
  for (const rel of io.listFiles(joinPath(out, BUNDLES_DIR))) {
    const path = `${BUNDLES_DIR}/${rel}`;
    served.set(path, io.readFile(joinPath(out, path)));
  }
  for (const path of [INDEX_PATH, REGISTRY_PATH]) {
    if (io.exists(joinPath(out, path))) served.set(path, io.readFile(joinPath(out, path)));
  }
  return served;
}

async function build(values: Values, io: Io): Promise<number> {
  const paths = pathsOf(values, io);
  const { manifest, files } = readManifestAndInputs(paths, io);
  const built = buildHost(manifest, files);
  for (const [path, bytes] of built.files) io.writeFile(joinPath(paths.out, path), bytes);
  const bundles = built.index.records.length;
  io.stdout(
    `build: wrote ${bundles} bundle${bundles === 1 ? '' : 's'}, ${built.registry ? `${REGISTRY_PATH} and ` : ''}${INDEX_PATH} to ${paths.out}\n`,
  );
  return EXIT.ok;
}

async function check(values: Values, io: Io): Promise<number> {
  const paths = pathsOf(values, io);
  const { manifest, files } = readManifestAndInputs(paths, io);
  const report = checkServed(buildHost(manifest, files).files, readServed(paths.out, io));
  io.stdout(`${report.lines.join('\n')}\n`);
  return report.ok ? EXIT.ok : EXIT.failed;
}

async function verify(values: Values, io: Io): Promise<number> {
  const paths = pathsOf(values, io);
  const report = await verifyServed(readServed(paths.out, io), io.verifyRecord ? { verifyRecord: io.verifyRecord } : {});
  io.stdout(`${report.lines.join('\n')}\n`);
  return report.ok ? EXIT.ok : EXIT.failed;
}

async function links(values: Values, io: Io): Promise<number> {
  const paths = pathsOf(values, io);
  const theme = values.theme ?? 'light';
  if (theme !== 'light' && theme !== 'dark') throw new HostError('--theme must be light or dark');
  const indexPath = joinPath(paths.out, INDEX_PATH);
  if (!io.exists(indexPath)) throw new HostError(`${indexPath} was not found; run build first`);
  const index = parseIndex(parseJsonFile(io.readFile(indexPath), indexPath), indexPath);
  io.stdout(serialize({ records: linksFor(index, theme as BadgeTheme) }));
  return EXIT.ok;
}

const COMMANDS: Record<string, (values: Values, io: Io) => Promise<number>> = { build, check, verify, links };

/** Run one command line; returns the exit code. Never throws. */
export async function run(argv: readonly string[], io: Io): Promise<number> {
  const [name, ...args] = argv;
  if (name === '--help' || name === '-h' || name === 'help') {
    io.stdout(USAGE);
    return EXIT.ok;
  }
  if (name === '--version') {
    io.stdout(`${JSON.stringify({ name: '@typedstandards/host-core', version: io.version })}\n`);
    return EXIT.ok;
  }
  const command = name === undefined ? undefined : COMMANDS[name];
  if (command === undefined) {
    io.stderr(`${name === undefined ? 'no command given' : `unknown command: ${name}`}\n\n${USAGE}`);
    return EXIT.usage;
  }
  let values: Values;
  try {
    values = io.parseArgs({ args, options: OPTIONS, strict: true, allowPositionals: false }).values as Values;
  } catch (err) {
    io.stderr(`typedstandards-host ${name}: ${(err as Error).message}\n`);
    return EXIT.usage;
  }
  if (values.theme !== undefined && name !== 'links') {
    io.stderr(`typedstandards-host ${name}: --theme applies to links only\n`);
    return EXIT.usage;
  }
  try {
    return await command(values, io);
  } catch (err) {
    if (err instanceof HostError) {
      io.stderr(`typedstandards-host ${name}: ${err.message}\n`);
      return EXIT.usage;
    }
    io.stderr(`typedstandards-host ${name}: internal error: ${(err as Error)?.stack ?? String(err)}\n`);
    return EXIT.internal;
  }
}
