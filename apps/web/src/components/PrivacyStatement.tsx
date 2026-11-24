import type { ReactNode } from "react";
import type { AnalyticsConfig } from "@/lib/analytics";
import { BARE_ID_ANCHOR } from "@/lib/host-directory";

/**
 * The body of `/privacy` (typedstandards#85): what this site does today. Each
 * statement is measured from the code and cited in the pull request that
 * wrote it, not here. The analytics section, and the clause naming it in
 * "Other sites", render only when `analytics` is set; the page passes the
 * same `SITE_ANALYTICS` the root layout renders the tag from.
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

function PlausibleSection() {
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
        To object, use an ad blocker or other content blocker that blocks{" "}
        <code className="font-mono">plausible.io</code>, or set the browser flag
        Plausible describes at{" "}
        <External href="https://plausible.io/docs/excluding-localstorage">
          plausible.io/docs/excluding-localstorage
        </External>
        . If your browser does not load Plausible&apos;s script, nothing is sent
        to <code className="font-mono">plausible.io</code>.
      </p>
    </Section>
  );
}

export function PrivacyStatement({ analytics }: { analytics: AnalyticsConfig | null }) {
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
        <p data-statement="hosting">
          Requests your browser sends to this site reach the service that hosts
          it, as requests to any website do. This site&apos;s own code keeps no
          record of them.
        </p>
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
      </Section>

      <Section id="storage" title="Cookies and storage">
        <p data-statement="storage">
          This site sets no cookies, and its code stores nothing in your browser.
        </p>
      </Section>

      <Section id="other-sites" title="Other sites">
        <p data-statement="other-sites">
          {plausible
            ? "Apart from the requests the verifier makes for a record you check, and the analytics described below, this site's pages ask your browser to contact no other site."
            : "Apart from the requests the verifier makes for a record you check, this site's pages ask your browser to contact no other site."}{" "}
          The fonts are served from this site, not from a font service.
        </p>
      </Section>

      {plausible && <PlausibleSection />}
    </div>
  );
}
