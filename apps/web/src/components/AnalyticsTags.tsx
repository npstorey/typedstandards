import { PLAUSIBLE_INIT, plausibleLoader, type AnalyticsConfig } from "@/lib/analytics";

/**
 * The analytics tag, or nothing (typedstandards#85). `null` renders nothing, so
 * a build with neither variable set asks no reader's browser to contact an
 * analytics service.
 *
 * Two inline scripts: the vendor's initializer, whose `transformRequest` is the
 * send gate around the redaction, then the loader, which inserts the vendor's
 * `async` script unless the reader turned analytics off in this browser (IMPL
 * TS-143; `analytics.ts`). No client module is imported, so a build without
 * analytics ships the same client code as one before this component existed.
 * The vendor's snippet works in either order: whichever of the two runs second
 * calls the vendor's `init` with the options the initializer passed
 * (plausible/analytics `tracker/src/plausible.js:58-65` at 0855e286).
 */
export function AnalyticsTags({ config }: { config: AnalyticsConfig | null }) {
  if (config === null) return null;
  if (config.service === "plausible") {
    return (
      <>
        <script id="plausible-init" dangerouslySetInnerHTML={{ __html: PLAUSIBLE_INIT }} />
        <script id="plausible-load" dangerouslySetInnerHTML={{ __html: plausibleLoader(config.id) }} />
      </>
    );
  }
  return null;
}
