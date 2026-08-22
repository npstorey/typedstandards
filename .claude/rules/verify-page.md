---
paths:
  - "apps/web/src/app/verify/**"
  - "apps/web/src/components/Verifier.tsx"
---

# Measuring `/verify` rendering

`/verify` renders **two** strings that open "A hash or slug carries no origin…", and
they are near-identical on purpose:

- the **static help paragraph** (`apps/web/src/app/verify/page.tsx:69`) always names
  the anchor, because it documents the default. Distinguishing words: "carries no
  origin **of its own**, so it **resolves** against";
- the **dynamic disclosure line** (`IdentifierResolutionNote` in
  `apps/web/src/components/Verifier.tsx:401`) names whichever host actually got
  resolved. Distinguishing phrase: **"so it is resolved against"**.

The help paragraph comes first in the document, so a `grep … | head -1` returns it
every time and makes a *working* `&host=` hint look inert. Anchor any resolution
measurement on `so it is resolved against`.
<!-- ts#58 P1: the host= hint was measured with a grep that matched the help paragraph and read as a failed render -->

Also: hostnames carry hyphens and more than one dot. A `[^.]*\.[a-z]+` window
truncates them and returns nothing, which likewise reads as a failed render.

## Where to measure

Preview deployments are access-protected — every path answers 302 to Vercel auth for
an unauthenticated client, so a curl-based "the preview renders X" check returns empty
matches that look like a failure. Scope rendering claims to the local `next build`
output and CI, and make production a named post-merge leg.
<!-- ts#52 gate: a preview curl returned 302/empty and was nearly reported as a render failure -->
