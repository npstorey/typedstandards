/**
 * Page analytics: whether the site renders Plausible's tag, and what that tag
 * sends (typedstandards#85).
 *
 * TWO VARIABLES, BOTH READ AT BUILD. `NEXT_PUBLIC_ANALYTICS_SERVICE` names the
 * service and `NEXT_PUBLIC_ANALYTICS_ID` the site's id with it, the same two
 * names the reference application reads. Neither set: no tag, so no reader's
 * browser is asked to contact any analytics service. Nothing here reads the
 * environment: `site-analytics.ts` reads each name literally and passes them
 * to `resolveAnalytics`, and `next.config.ts` lists both under `env`, so
 * `next build` replaces each with its value in server code as well as browser
 * code. Without that, Next 16's server build keeps `process.env.NEXT_PUBLIC_…`
 * as a read at render time, and the dynamic `/verify` routes would decide per
 * request while prerendered pages, `/privacy` among them, keep the build's
 * values (measured, typedstandards#85).
 *
 * THE RULE, the reference application's (civic-ai-tools-website
 * `src/lib/analytics-config.ts` at 407b68c) without its prior-era variable,
 * which this site never had:
 *   - empty, or whitespace alone, counts as absent;
 *   - both present and the service known: that service with that id;
 *   - anything else (an unknown service, or one of the pair without the
 *     other) renders nothing.
 * `plausible` is the only service. Its id is the per-site script key the
 * vendor's site settings show (`pa-` followed by an id), which names the
 * script file.
 *
 * WHAT THE TAG IS. The vendor's own snippet, read 2026-11-24 from the vendor's
 * open-source repository (plausible/analytics
 * `lib/plausible_web/live/installation/instructions.ex:178-183` at 0855e286):
 * an `async` script from `https://plausible.io/js/<id>.js`, and an inline
 * initializer whose first line is the vendor's, unchanged. Its second line
 * passes `transformRequest` to `plausible.init`, below.
 */

export const ANALYTICS_SERVICES = ['plausible'] as const;
export type AnalyticsService = (typeof ANALYTICS_SERVICES)[number];

export interface AnalyticsEnv {
  NEXT_PUBLIC_ANALYTICS_SERVICE?: string;
  NEXT_PUBLIC_ANALYTICS_ID?: string;
}

export interface AnalyticsConfig {
  service: AnalyticsService;
  id: string;
}

/** A set value, trimmed; `null` for unset, empty, or whitespace alone. */
function present(raw: string | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const value = raw.trim();
  return value === '' ? null : value;
}

function isService(value: string): value is AnalyticsService {
  return (ANALYTICS_SERVICES as readonly string[]).includes(value);
}

export function resolveAnalytics(env: AnalyticsEnv): AnalyticsConfig | null {
  const service = present(env.NEXT_PUBLIC_ANALYTICS_SERVICE);
  const id = present(env.NEXT_PUBLIC_ANALYTICS_ID);
  if (service === null || id === null || !isService(service)) return null;
  return { service, id };
}

/** The vendor's script, for a site's script key. */
export function plausibleScriptSrc(id: string): string {
  return `https://plausible.io/js/${id}.js`;
}

/** The first line of the vendor's initializer, byte for byte. */
export const PLAUSIBLE_QUEUE =
  'window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};';

/**
 * THE REDACTION, as the JavaScript the browser runs: the `transformRequest`
 * function the initializer hands to `plausible.init`. It is kept as source
 * text, not as a TypeScript function, so the bytes the page renders are the
 * bytes `analytics.test.ts` runs: the test evaluates `PLAUSIBLE_INIT` itself
 * and drives the function it passes.
 *
 * WHERE IT RUNS (plausible/analytics `tracker/src/track.js:86-163` at
 * 0855e286). The script builds each event's payload, with the page address in
 * `u` (`location.href`), the referrer in `r` (`document.referrer`) and any
 * properties in `p`, calls `transformRequest` on it, sends what it returns,
 * and sends nothing when it returns a falsy value. Every pageview and every
 * other event goes through it, the first pageview included: the vendor's
 * script tracks that pageview inside `init`, which receives these options
 * whether the inline line or the script runs first (`tracker/src/plausible.js`).
 * Engagement events carry the pageview's `u` and `p` as this function
 * returned them (`tracker/src/engagement.js:34-38, 67-75`).
 *
 * WHAT IT DOES. It reads nothing but the payload.
 *   - A verify address is one whose path is `/verify`, or begins `/verify/`,
 *     in any letter case. Its path becomes `/verify`, or `/verify/[record]`
 *     when anything follows `/verify/`, and its query and fragment are dropped:
 *     `?url=`, `?hash=` and `&host=` carry what a reader verifies (the
 *     `/verify` page), and the path carries the identifier and its host (the
 *     `/verify/[...target]` page, `parseVerifyTarget`). No other page of this
 *     site reads its address.
 *   - The page address `u`, when it is a verify address, is redacted so.
 *   - The referrer `r`, when it has the page's own host (either scheme) and is
 *     a verify address, is redacted so. A referrer from any other host, and a
 *     same-host referrer that is not a verify address, is left as it is.
 *   - An event sent from a verify page carries no properties: the vendor's
 *     outbound-link and file-download events put the link's address in
 *     `p.url` (`tracker/src/custom-events.js:92-107`), and the vendor's site
 *     settings, not this code, turn them on.
 *   - A page address that does not parse drops the event; a referrer that does
 *     not parse is dropped.
 * Every other payload field, and every other page's address, is left as the
 * vendor's script built it.
 */
export const PLAUSIBLE_REDACT =
  'function(payload){' +
  'function verifyPath(url){' +
  "var path=url.pathname.toLowerCase();" +
  "if(path==='/verify'||path==='/verify/')return '/verify';" +
  "if(path.indexOf('/verify/')===0)return '/verify/[record]';" +
  'return null}' +
  'var page;' +
  'try{page=new URL(payload.u)}catch(e){return null}' +
  'var pagePath=verifyPath(page);' +
  'if(pagePath!==null){payload.u=page.origin+pagePath;delete payload.p}' +
  'if(payload.r){' +
  'var ref;' +
  'try{ref=new URL(payload.r)}catch(e){payload.r=null;return payload}' +
  'if(ref.host===page.host){' +
  'var refPath=verifyPath(ref);' +
  'if(refPath!==null)payload.r=ref.origin+refPath}' +
  '}' +
  'return payload}';

/** The inline initializer: the vendor's first line, then `plausible.init` with the redaction. */
export const PLAUSIBLE_INIT = `${PLAUSIBLE_QUEUE}\nplausible.init({transformRequest:${PLAUSIBLE_REDACT}})`;
