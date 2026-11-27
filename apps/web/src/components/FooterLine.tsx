/**
 * The footer's first line. With the lookup count (typedstandards#143; IMPL
 * TS-143) it is S161[1], whose pointer links the privacy page's note on the
 * count; without it, the line as it was.
 */
export function FooterLine({ lookupCount }: { lookupCount: boolean }) {
  return (
    <p>
      Typed Standards — signed records you can verify yourself. Verification
      runs in your browser; nothing is uploaded.
      {lookupCount && (
        <>
          {" "}
          This site counts records you verify from links you open, by website and
          day; see{" "}
          <a href="/privacy#lookups" className="underline decoration-dotted hover:text-accent">
            the privacy page
          </a>
          .
        </>
      )}
    </p>
  );
}
