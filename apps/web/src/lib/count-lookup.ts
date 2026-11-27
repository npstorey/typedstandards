import { after } from "next/server";
import { headers } from "next/headers";
import { LOOKUP_WRITE_TIMEOUT_MS, recordLookup, type LookupTotals } from "./lookup-count.ts";
import { SITE_LOOKUP_COUNT, siteLookupStore } from "./site-lookup-count.ts";

/**
 * Count this request's lookup, after the response (typedstandards#143; IMPL
 * TS-143). The two verify pages call it with the input and host they hand the
 * Verifier, so the count reads the lookup as the verifier does. Nothing happens
 * unless this build counts; the write runs in Next's `after()`, so the reader
 * never waits on it, and `recordLookup` never throws.
 */
export async function countLookup(input: string, hintedHost: string | undefined): Promise<void> {
  if (!SITE_LOOKUP_COUNT) return;
  const requestHeaders = new Headers(await headers());
  after(async () => {
    await recordLookup({ input, hintedHost, headers: requestHeaders, store: await siteLookupStore() });
  });
}

/** The totals for `/privacy`, or `null` when nothing is counted yet or the read fails. */
export async function lookupTotals(): Promise<LookupTotals | null> {
  if (!SITE_LOOKUP_COUNT) return null;
  try {
    const store = await siteLookupStore();
    if (!store) return null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), LOOKUP_WRITE_TIMEOUT_MS);
    });
    try {
      return await Promise.race([store.totals(), timeout]);
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    console.error(`lookup count: totals read failed (${err instanceof Error ? err.name : typeof err})`);
    return null;
  }
}
