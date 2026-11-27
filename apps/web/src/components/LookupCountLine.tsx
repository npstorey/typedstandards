/**
 * S162[1] (typedstandards#143; IMPL TS-143): the lines after the intro of
 * `/verify` and of a record's own page, where a counted link lands (the seat's
 * ruling 7227111427, reading 6). Rendered only with the lookup count; its first
 * words link the privacy page's note on the count.
 */
export function LookupCountLine() {
  return (
    <p data-statement="lookup-count" className="mt-4 max-w-2xl text-sm leading-relaxed text-muted">
      <a href="/privacy#lookups" className="underline decoration-dotted hover:text-accent">
        This site counts
      </a>
      , each day, the website of a record you verify from a link you open, never
      the record. Dropping in a saved bundle, or verifying offline, is not counted.
    </p>
  );
}
