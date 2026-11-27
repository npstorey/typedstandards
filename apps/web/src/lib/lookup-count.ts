/**
 * The verifier's lookup count (typedstandards#143 by (i); IMPL TS-143).
 *
 * WHAT IS COUNTED. A link lookup: a request to `/verify` with `?url=` or
 * `?hash=` (and `&host=`), or to `/verify/<id>` or `/verify/<host>/<id>`. Each
 * adds one to its host's row for that UTC day: lookups, not unique visitors.
 * The host is the one the verifier fetches the record from, read as
 * `Verifier.run` reads its input: trimmed, `detectInputMode`, then the first
 * commitment candidate against the host the link names or the anchor. A typed
 * or pasted lookup and a dropped bundle never reach the server (the verifier
 * runs in place and writes its address with `replaceState`), so they are not
 * counted, by design.
 *
 * WHAT IS NOT COUNTED (the seat's ruling 7227111427):
 *   - a bundle in `?url=`, or no input;
 *   - a non-public host: an IP literal, a single label, or a special-use
 *     suffix (`.local`, `.localhost`, `.internal`, `.home.arpa`, `.test`,
 *     `.invalid`, `.example`);
 *   - a request Next's `userAgent()` marks as a bot (a crawler, a link
 *     preview), and a prefetch (`Next-Router-Prefetch`, `Sec-Purpose` or
 *     `Purpose`): neither is a record a reader verifies from a link they open.
 *     The headers are read and not kept.
 *
 * WHAT IS KEPT. One row per (day, host) with its count, in the table
 * `apps/web/lookup-counts.sql` defines. Nothing else: no network address, no
 * cookie, no identifier, no path, never the record. `recordLookup` is the one
 * writer; the store receives the day and the host and nothing more.
 *
 * WHEN. The two verify pages call it through `countLookup` (`count-lookup.ts`)
 * with Next's `after()`, so the write starts after the response and the
 * reader never waits on it. A write is bounded by `LOOKUP_WRITE_TIMEOUT_MS`;
 * a failed one is logged as a class only (the error's name and code), never
 * its message, which can carry an address.
 */

import { userAgent } from 'next/server';
import {
  bareIdCommitmentUrlCandidates,
  DEFAULT_HOST,
  deriveCommitmentUrlCandidates,
  detectInputMode,
} from './verify-flow.ts';

/** How long a write may take before it is abandoned and logged. */
export const LOOKUP_WRITE_TIMEOUT_MS = 10_000;

/** The count across all hosts: what this site publishes until #142's index exists. */
export interface LookupTotals {
  firstDay: string;
  lastDay: string;
  lookups: number;
}

export interface LookupStore {
  increment(day: string, host: string): Promise<void>;
  totals(): Promise<LookupTotals | null>;
}

const SPECIAL_USE = ['.local', '.localhost', '.internal', '.home.arpa', '.test', '.invalid', '.example'];

/** Whether a hostname, as `URL` reports it, names a public website. */
export function isPublicHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[') || host.includes(':')) return false; // an IPv6 literal
  if (/^\d+(\.\d+){3}$/.test(host)) return false; // an IPv4 literal, as URL normalizes one
  if (!host.includes('.')) return false; // a single label, localhost among them
  return !SPECIAL_USE.some((suffix) => host.endsWith(suffix));
}

/** The host a lookup counts under, or `null` when it is not counted. */
export function lookupHost(input: string, hintedHost?: string): string | null {
  const s = input.trim();
  if (!s) return null;
  const mode = detectInputMode(s);
  if (mode === 'bundle') return null;
  const host = hintedHost ?? DEFAULT_HOST;
  let hostname: string;
  try {
    const first = mode === 'hash' ? bareIdCommitmentUrlCandidates(s, host)[0] : deriveCommitmentUrlCandidates(s, host)[0];
    hostname = new URL(first).hostname.replace(/\.$/, '');
  } catch {
    return null;
  }
  return isPublicHost(hostname) ? hostname : null;
}

/** The UTC date of a time, as `YYYY-MM-DD`. */
export function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** Whether a request is a reader opening the page: not a bot, not a prefetch. */
function isReaderRequest(headers: Headers): boolean {
  if (headers.get('next-router-prefetch') !== null) return false;
  if (/prefetch/i.test(headers.get('sec-purpose') ?? headers.get('purpose') ?? '')) return false;
  return !userAgent({ headers }).isBot;
}

function errorClass(err: unknown): string {
  if (err instanceof Error) {
    const code = (err as { code?: unknown }).code;
    return typeof code === 'string' && /^[A-Za-z0-9_]{1,16}$/.test(code) ? `${err.name} ${code}` : err.name;
  }
  return typeof err;
}

const TIMEOUT = Symbol('timeout');

/**
 * Count one lookup, if it is one: the store's `increment(day, host)` or
 * nothing. Never throws.
 */
export async function recordLookup(opts: {
  input: string;
  hintedHost?: string;
  headers: Headers;
  store: LookupStore | null;
  now?: number;
  log?: (line: string) => void;
  timeoutMs?: number;
}): Promise<'counted' | 'not-counted' | 'failed'> {
  const log = opts.log ?? ((line: string) => console.error(line));
  const host = lookupHost(opts.input, opts.hintedHost);
  if (host === null || !isReaderRequest(opts.headers)) return 'not-counted';
  if (opts.store === null) {
    log('lookup count: write failed (no store)');
    return 'failed';
  }
  const day = utcDay(opts.now ?? Date.now());
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<typeof TIMEOUT>((resolve) => {
    timer = setTimeout(() => resolve(TIMEOUT), opts.timeoutMs ?? LOOKUP_WRITE_TIMEOUT_MS);
  });
  try {
    const outcome = await Promise.race([opts.store.increment(day, host), timeout]);
    if (outcome === TIMEOUT) {
      log('lookup count: write failed (timeout)');
      return 'failed';
    }
    return 'counted';
  } catch (err) {
    log(`lookup count: write failed (${errorClass(err)})`);
    return 'failed';
  } finally {
    clearTimeout(timer);
  }
}

/** The upsert: one more lookup for (day, host). */
export const INCREMENT_SQL =
  'INSERT INTO lookup_counts (day, host, lookups) VALUES ($1::date, $2, 1) ' +
  'ON CONFLICT (day, host) DO UPDATE SET lookups = lookup_counts.lookups + 1';

/** The totals across all hosts, the first and last day counted: it names no host. */
export const TOTALS_SQL =
  "SELECT to_char(min(day), 'YYYY-MM-DD') AS first_day, to_char(max(day), 'YYYY-MM-DD') AS last_day, " +
  'coalesce(sum(lookups), 0)::text AS lookups FROM lookup_counts';

/** A store over a parameterized query function (the Neon driver's `sql.query`). */
export function sqlLookupStore(query: (text: string, params: unknown[]) => Promise<Record<string, unknown>[]>): LookupStore {
  return {
    async increment(day, host) {
      await query(INCREMENT_SQL, [day, host]);
    },
    async totals() {
      const [row] = await query(TOTALS_SQL, []);
      const lookups = Number(row?.lookups ?? 0);
      if (!row || !lookups || typeof row.first_day !== 'string' || typeof row.last_day !== 'string') return null;
      return { firstDay: row.first_day, lastDay: row.last_day, lookups };
    },
  };
}
