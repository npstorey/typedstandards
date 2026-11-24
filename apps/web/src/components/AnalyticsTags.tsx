import { PLAUSIBLE_INIT, plausibleScriptSrc, type AnalyticsConfig } from "@/lib/analytics";

/**
 * The analytics tag, or nothing (typedstandards#85). `null` renders nothing, so
 * a build with neither variable set asks no reader's browser to contact an
 * analytics service.
 *
 * Plain `<script>` elements, as the vendor's snippet is: no client module is
 * imported, so a build without analytics ships the same client code as one
 * before this component existed. React hoists the `async` script into the
 * document head; the initializer runs where it is rendered. The vendor's
 * snippet works in either order: whichever of the two runs second calls the
 * vendor's `init` with the options the initializer passed
 * (plausible/analytics `tracker/src/plausible.js:58-65` at 0855e286).
 */
export function AnalyticsTags({ config }: { config: AnalyticsConfig | null }) {
  if (config === null) return null;
  if (config.service === "plausible") {
    return (
      <>
        <script async src={plausibleScriptSrc(config.id)} />
        <script id="plausible-init" dangerouslySetInnerHTML={{ __html: PLAUSIBLE_INIT }} />
      </>
    );
  }
  return null;
}
