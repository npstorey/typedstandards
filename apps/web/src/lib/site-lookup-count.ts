import { sqlLookupStore, type LookupStore } from "./lookup-count.ts";

/**
 * Whether this build counts lookups (typedstandards#143; IMPL TS-143), decided
 * once at build: `next.config.ts` sets `TYPEDSTANDARDS_LOOKUP_COUNT` to "on"
 * when `LOOKUP_COUNT_DATABASE_URL` is set, and inlines only that word, never the
 * address. The footer, the two verify pages and `/privacy` say the count's words
 * only when it is on, and the two verify pages count only when it is on, so the
 * words and the count cannot disagree.
 */
export const SITE_LOOKUP_COUNT = process.env.TYPEDSTANDARDS_LOOKUP_COUNT === "on";

let store: Promise<LookupStore | null> | undefined;

/**
 * The count's store: the Neon database at `LOOKUP_COUNT_DATABASE_URL`, read on
 * the server at run time, through the driver's HTTP query. `null` when the
 * address is not set where the page runs. The driver is loaded only here.
 */
export function siteLookupStore(): Promise<LookupStore | null> {
  store ??= (async () => {
    const url = process.env.LOOKUP_COUNT_DATABASE_URL;
    if (!url) return null;
    const { neon } = await import("@neondatabase/serverless");
    const sql = neon(url);
    return sqlLookupStore((text, params) => sql.query(text, params) as Promise<Record<string, unknown>[]>);
  })();
  return store;
}
