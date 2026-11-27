import type { ReactNode } from "react";
import { dashboardLabel, type AnalyticsConfig } from "@/lib/analytics";
import { ANALYTICS_MEMORY_KEY, holderOf } from "@/lib/analytics-notice";
import { BARE_ID_ANCHOR } from "@/lib/host-directory";
import { AnalyticsChoice } from "@/components/AnalyticsChoice";
import type { LookupTotals } from "@/lib/lookup-count";

/**
 * The body of `/privacy` (typedstandards#85): what this site does today. Each
 * statement is measured from the code and cited in the pull request that
 * wrote it, not here. The analytics section, and the clause naming it in
 * "Other sites", render only when `analytics` is set; the page passes the
 * same `SITE_ANALYTICS` the root layout renders the tag from. The section's
 * dashboard line renders only when that config also carries a dashboard
 * address (ruling D7; the seat's amendment on #85, 7146352815). With the tag,
 * the storage statement says what the analytics notice keeps (W6), and the
 * analytics section carries the way back, `AnalyticsChoice` (IMPL TS-143).
 */

/** The date the vendor pages cited below were read. */
export const PLAUSIBLE_READ_DATE = "2026-11-24";

/** The bare-identifier anchor as a bare hostname, from the verifier's own constant. */
const anchorHost = (() => {
  try {
    return new URL(BARE_ID_ANCHOR).host;
  } catch {
    return BARE_ID_ANCHOR;
  }
})();

const LINK = "underline decoration-dotted hover:text-accent";

/** The command-line tool, `packages/cli`, whose README states it "makes no
 *  network request" (`packages/cli/README.md:12-13`; owner's request, the seat's
 *  ruling on #85, 7168511887). */
export const CLI_URL = "https://github.com/npstorey/typedstandards/tree/main/packages/cli";

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className="mt-10">
      <h2 className="font-display text-xl font-semibold tracking-tight">{title}</h2>
      <div className="mt-3 space-y-3 leading-relaxed">{children}</div>
    </section>
  );
}

function External({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={LINK}>
      {children}
    </a>
  );
}

function PlausibleSection({ dashboardUrl, holder }: { dashboardUrl: string | undefined; holder: string }) {
  return (
    <Section id="analytics" title="Analytics">
      <p data-statement="analytics-what">
        This site counts visits with Plausible Analytics. Your browser loads
        Plausible&apos;s script from <code className="font-mono">plausible.io</code>.
        For each page you view, the script sends Plausible the page&apos;s address,
        the address of the page that linked you to it, and how long you spent on
        the page and how far you scrolled. Depending on this site&apos;s settings
        with Plausible, a click on a link to another site, or on a file download,
        also sends that link&apos;s address.
      </p>
      <p data-statement="analytics-redaction">
        Before anything is sent, the script removes what you verify. The address
        of a verify page is sent as <code className="font-mono">/verify</code>, or
        as <code className="font-mono">/verify/[record]</code> for a record&apos;s
        own page, with nothing after it. The address of the page that linked you
        is shortened the same way when it is a verify page on this site. A click
        on a link from a verify page is sent without the link&apos;s address.
      </p>
      {dashboardUrl && (
        <p data-statement="analytics-dashboard">
          Plausible&apos;s counts for this site are public: anyone can see them at{" "}
          <External href={dashboardUrl}>{dashboardLabel(dashboardUrl)}</External>.
        </p>
      )}
      <p data-statement="analytics-vendor">
        Plausible says it sets no cookies and stores nothing in your browser. Each
        request carries your network address and your browser&apos;s user agent, as
        any request does; Plausible says it uses them to count a day&apos;s unique
        visitors and to tell your browser, device and approximate location, and
        does not store them. Plausible says that of a page address it keeps the
        site name and the path, and discards the query part, except the parts it
        uses to tell where a visit came from, such as a campaign or a referring
        site (its{" "}
        <External href="https://plausible.io/data-policy">data policy</External>,
        read {PLAUSIBLE_READ_DATE}).
      </p>
      <p data-statement="analytics-objection">
        To object, turn analytics off on this page, or use an ad blocker or other
        content blocker that blocks{" "}
        <code className="font-mono">plausible.io</code>, or set the browser flag
        Plausible describes at{" "}
        <External href="https://plausible.io/docs/excluding-localstorage">
          plausible.io/docs/excluding-localstorage
        </External>
        . If your browser does not load Plausible&apos;s script, nothing is sent
        to <code className="font-mono">plausible.io</code>.
      </p>
      <AnalyticsChoice holder={holder} />
    </Section>
  );
}

/** W6 (IMPL TS-143; ND-M-2 B, ND-H-2 A): what the analytics notice keeps, where, and for how long. */
function StorageWithAnalytics() {
  return (
    <p data-statement="storage">
      This site sets no cookies. It remembers that you hid its message, and that
      you turned analytics off if you did. It keeps both in your browser&apos;s
      storage for this site, under the name{" "}
      <code className="font-mono">{ANALYTICS_MEMORY_KEY}</code>, for six months.
    </p>
  );
}

/** A day counted, as a reader reads it: `2026-11-27` → "November 27, 2026". */
function longDay(day: string): string {
  return new Date(`${day}T00:00:00Z`).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "UTC",
  });
}

/**
 * S163[1] in its totals-only form (W7), under W9, with the totals (W8):
 * typedstandards#143's note on the lookup count, which the footer and the
 * verify pages link (`#lookups`). Its third sentence is W7: this site's
 * publisher index (#142) does not exist yet, so only totals are published.
 */
function LookupsSection({ totals }: { totals: LookupTotals | null }) {
  return (
    <Section id="lookups" title="What this site counts">
      <p data-statement="lookups">
        This site counts the website of each record you verify from a link you
        open, and the day. The count keeps no network address, no cookie, no
        identifier, and never the record. This site publishes only the totals
        across all websites. To verify without being counted, drop in a saved
        bundle, or verify offline with the{" "}
        <External href={CLI_URL}>command-line tool</External>. When any verifier
        fetches a record, that record&apos;s own server sees the fetch. Only
        verifying a saved bundle offline avoids that.
      </p>
      {totals && (
        <p data-statement="lookup-totals">
          Lookups counted across all websites from {longDay(totals.firstDay)} to{" "}
          {longDay(totals.lastDay)}: {totals.lookups.toLocaleString("en-US")}.
        </p>
      )}
    </Section>
  );
}

export function PrivacyStatement({
  analytics,
  lookupCount = null,
}: {
  analytics: AnalyticsConfig | null;
  /** The lookup count (typedstandards#143), when this build counts; its totals when any are counted. */
  lookupCount?: { totals: LookupTotals | null } | null;
}) {
  const plausible = analytics?.service === "plausible";
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
        Privacy
      </p>
      <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">
        What this site does with your visit
      </h1>
      <p className="mt-4 max-w-2xl leading-relaxed text-muted">
        What typedstandards.org does when you read it, and when you verify a
        record with it.
      </p>

      <Section id="serves" title="What this site serves">
        <p data-statement="serves">
          This site serves its pages and the scripts, styles, fonts and images
          they use. It also serves two files other sites may read: the list of
          publishers it recognizes, and the verify badge image.
        </p>
        {lookupCount ? (
          <p data-statement="hosting">
            Requests your browser sends to this site reach the service that hosts
            it, as requests to any website do. This site&apos;s own code keeps no
            record of them beyond the daily count described below.
          </p>
        ) : (
          <p data-statement="hosting">
            Requests your browser sends to this site reach the service that hosts
            it, as requests to any website do. This site&apos;s own code keeps no
            record of them.
          </p>
        )}
      </Section>

      <Section id="verify" title="When you verify a record">
        <p data-statement="verify-where">
          The verifier runs in your browser: your browser fetches the record and
          checks it on your device.
        </p>
        <p data-statement="verify-fetches">
          Your browser fetches the record from a publisher&apos;s site: the one the
          address you paste or follow names, or, for a hash or slug on its own,{" "}
          {anchorHost} unless the link names another publisher or you pick one. The
          record then names the other addresses your browser fetches: its
          package, the publisher&apos;s key registry, files the record refers to,
          and, when the record names an entry in Sigstore&apos;s public transparency
          log without carrying its proof, that entry at{" "}
          <code className="font-mono">rekor.sigstore.dev</code>. Your browser also
          fetches from this site the list of publishers it recognizes.
        </p>
        <p data-statement="verify-requests">
          Each of those requests goes from your browser to the site it names and,
          like any request, carries your network address there.
        </p>
        <p data-statement="verify-input">
          What you type or paste into the verifier, and a bundle you drop in, stay
          in your browser: the verifier sends none of it to this site. A bundle is
          checked with what it carries; your browser fetches only what the bundle
          names but does not carry, and a bundle that carries everything is
          checked without any request.
        </p>
        <p data-statement="verify-links">
          A link to a record on this site, such as{" "}
          <code className="font-mono">/verify/&lt;id&gt;</code>, is an address like
          any other: when you open it, it reaches this site&apos;s server.
        </p>
        {lookupCount && (
          <p data-statement="verify-count">
            This site counts, each day, the website of a record you verify from a
            link you open, and the count keeps nothing else.
          </p>
        )}
        <p data-statement="verify-locally">
          You can also verify a record on your own computer: the{" "}
          <External href={CLI_URL}>command-line tool</External> reads it from a file
          and makes no network request.
        </p>
      </Section>

      <Section id="storage" title="Cookies and storage">
        {plausible ? (
          <StorageWithAnalytics />
        ) : (
          <p data-statement="storage">
            This site sets no cookies, and its code stores nothing in your browser.
          </p>
        )}
      </Section>

      <Section id="other-sites" title="Other sites">
        <p data-statement="other-sites">
          {plausible
            ? "Apart from the requests the verifier makes for a record you check, and the analytics described below, this site's pages ask your browser to contact no other site."
            : "Apart from the requests the verifier makes for a record you check, this site's pages ask your browser to contact no other site."}{" "}
          The fonts are served from this site, not from a font service.
        </p>
      </Section>

      {lookupCount && <LookupsSection totals={lookupCount.totals} />}

      {plausible && <PlausibleSection dashboardUrl={analytics.dashboardUrl} holder={holderOf(analytics)} />}
    </div>
  );
}
