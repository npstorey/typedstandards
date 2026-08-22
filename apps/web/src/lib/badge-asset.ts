// Embeddable verify badge (#116 WS3 Phase E, ADR-0013 / Q46) — the asset + the
// embed-snippet builders.
//
// THE LOAD-BEARING HONESTY CONSTRAINT. The badge is a CALL TO ACTION ("verify this
// independently"), NOT a verdict. It must never read "verified" / pass-fail on a
// host's page: that would be a claim the badge cannot back AND trivially forgeable
// (anyone can paste a green check). The real verdict appears ONLY at
// typedstandards.org/verify, after the §9.2 checks run in the reader's browser. So
// the mark is a calm wordmark + an INSPECT glyph (a magnifier — an action, not a
// state) and the imperative "Verify with Typed Standards" — deliberately no
// checkmark, no green tier, no "valid". (P1: disclosure ≠ validation.)
//
// Dependency-free on purpose: the SVG route handler imports `renderBadgeSvg` and
// nothing here pulls in verify-core / the verify flow, so the badge asset stays a
// tiny, self-contained image.

/** The canonical production origin. The COPY-PASTE SNIPPET hardcodes this so a
 *  host that pastes it always points at the real neutral verifier (never a preview
 *  or relative path). The live preview on /badge uses a same-origin relative URL
 *  instead, so a preview deployment shows its own badge. */
export const CANONICAL_ORIGIN = 'https://typedstandards.org';

/** Stable, CORS-fetchable path of the badge asset (served by the route handler).
 *  `?theme=dark` selects the dark variant. */
export const BADGE_ASSET_PATH = '/badge/typed-standards-verify.svg';

/** Intrinsic badge dimensions (also used for the embed `<img>` width/height). */
export const BADGE_WIDTH = 248;
export const BADGE_HEIGHT = 30;

export type BadgeTheme = 'light' | 'dark';

/** Plain-language alt text for the embed `<img>` — describes the ACTION, not a
 *  verdict, consistent with the honesty constraint.
 *
 *  VOCABULARY CUTOVER (2026-08-21, typedstandards#52; spec Appendix J): the wording
 *  moved from "this evidence" to "this record". Every NEW emission carries the new
 *  text — the served SVG's `aria-label` + `<title>`, the copy-paste HTML and
 *  Markdown embeds, and the /badge preview. Prior-era embeds keep working — src
 *  unchanged: `BADGE_ASSET_PATH` is untouched, so an `<img>` pasted before the
 *  cutover still resolves (and now shows the new SVG title); only the `alt` frozen
 *  in that host page keeps the old wording, and shipped third-party embeds are not
 *  chased. The literal is pinned in badge-asset.test.ts, independent of this
 *  constant, so a revert here fails a test rather than passing silently. */
export const BADGE_ALT = 'Verify this record with Typed Standards';

/**
 * Render the badge as a self-contained SVG string (no external fonts/resources, so
 * it renders identically when loaded via `<img>`). A calm pill: an inspect glyph
 * (magnifier) + "Verify with Typed Standards", the brand word in the accent color.
 * Light and dark variants only differ in the palette — never in the wording.
 */
export function renderBadgeSvg(theme: BadgeTheme = 'light'): string {
  const dark = theme === 'dark';
  const bg = dark ? '#0a0a0a' : '#ffffff';
  const border = dark ? '#2a2a30' : '#e4e4e7';
  const cta = dark ? '#a1a1aa' : '#5b5b5b';
  const brand = dark ? '#6699ff' : '#1452ff';
  const w = BADGE_WIDTH;
  const h = BADGE_HEIGHT;
  const rx = (h - 1.5) / 2;
  const font =
    "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${BADGE_ALT}">
  <title>${BADGE_ALT}</title>
  <rect x="0.75" y="0.75" width="${w - 1.5}" height="${h - 1.5}" rx="${rx}" fill="${bg}" stroke="${border}" stroke-width="1.5"/>
  <g fill="none" stroke="${brand}" stroke-width="1.6" stroke-linecap="round">
    <circle cx="21" cy="14" r="4.3"/>
    <line x1="24" y1="17" x2="27.2" y2="20.2"/>
  </g>
  <text x="37" y="19.4" font-family="${font}" font-size="12.5">
    <tspan fill="${cta}">Verify with </tspan><tspan fill="${brand}" font-weight="600">Typed Standards</tspan>
  </text>
</svg>
`;
}

// --- Embed-snippet builders ----------------------------------------------

/** Classify a badge input. `bundle` (pasted JSON) is unsupported — a badge links
 *  to a resolvable URL/identifier, not an inline document. */
export type BadgeInputKind = 'url' | 'hash' | 'bundle' | 'empty';

export function classifyBadgeInput(raw: string): BadgeInputKind {
  const s = raw.trim();
  if (!s) return 'empty';
  if (s.startsWith('{')) return 'bundle';
  if (/^https?:\/\//i.test(s)) return 'url';
  return 'hash'; // 64-hex hash OR a record slug — both resolve by identifier
}

/**
 * Build the verifier deep-link for a package input. A hosted URL goes through
 * `?url=` (host-independent — works for any publisher, resolved by the verifier's
 * deriveCommitmentUrl); a bare hash/slug uses the `?hash=` shorthand. `origin` is
 * `''` for a same-origin (relative) link.
 *
 * `hostHint` is the OPTIONAL publisher origin a bare hash/slug should resolve
 * against (typedstandards#58), emitted as `&host=<origin>` and read back by
 * `/verify` through `parseHostHint`. Omitted for a `?url=` input, which already
 * carries an origin, and omitted for `bundle`/`empty`, which are not badgeable.
 * Without it a bare identifier keeps today's behaviour exactly: it resolves against
 * the directory's declared anchor.
 *
 * Two deliberate choices here, both load-bearing:
 *
 *  1. THE CALLER VALIDATES. `hostHint` must already be a canonical
 *     `https://<host>` origin — what `parseHostHint` (host-directory) returns, or
 *     `undefined`. This module is dependency-free on purpose (the SVG route handler
 *     imports `renderBadgeSvg` from it, and /badge keeps the verification core out
 *     of its bundle), so the shape grammar is NOT imported here and NOT restated
 *     here. One implementation, in one place.
 *  2. THE ORIGIN IS EMITTED UNENCODED. `:` and `/` are legal in a query component
 *     (RFC 3986 §3.4: `query = *( pchar / "/" / "?" )`, and `pchar` admits `:`),
 *     so `&host=https://example.org` is a well-formed URL and is the exact string a
 *     publisher is handed — the same characters in the preview link, the "Links to"
 *     line, and both snippets. The package input keeps its
 *     `encodeURIComponent`: it is arbitrary user text, where the host hint is a
 *     validated origin.
 */
export function buildVerifyHref(origin: string, input: string, hostHint?: string): string {
  const s = input.trim();
  const kind = classifyBadgeInput(s);
  const param = kind === 'url' ? 'url' : 'hash';
  const hint = kind === 'hash' && hostHint ? `&host=${hostHint}` : '';
  return `${origin}/verify?${param}=${encodeURIComponent(s)}${hint}`;
}

/** Full badge asset URL for the given origin + theme. */
export function badgeAssetUrl(origin: string, theme: BadgeTheme = 'light'): string {
  return `${origin}${BADGE_ASSET_PATH}${theme === 'dark' ? '?theme=dark' : ''}`;
}

/** The copy-paste HTML embed: an `<a>` (deep-link) wrapping the badge `<img>`.
 *
 *  A `&host=` hint puts a raw `&` in the `href` attribute. That is correct HTML: an
 *  `&` is an AMBIGUOUS AMPERSAND (and so a parse error) only when alphanumerics
 *  after it are terminated by `;`, and `&host=` is terminated by `=`, so every HTML5
 *  tokenizer emits the character literally. Escaping it to `&amp;` would also work
 *  in a browser, but would make the string a publisher copies out of this snippet
 *  differ from the link shown everywhere else on the page — and a hand-copied
 *  `&amp;` in a plain-text context is a broken link. One string, everywhere. */
export function buildEmbedHtml(
  origin: string,
  input: string,
  theme: BadgeTheme = 'light',
  hostHint?: string,
): string {
  const href = buildVerifyHref(origin, input, hostHint);
  const src = badgeAssetUrl(origin, theme);
  return `<a href="${href}">
  <img src="${src}" alt="${BADGE_ALT}" width="${BADGE_WIDTH}" height="${BADGE_HEIGHT}" />
</a>`;
}

/** The copy-paste Markdown embed (linked image). The deep-link href is wrapped in
 *  angle brackets (`](<...>)`) — CommonMark's destination-in-`<>` form — so a `)`
 *  in the URL (rare, but legal in a hosted commitment URL) does not prematurely
 *  close the link. The package input is `encodeURIComponent`-encoded and an optional
 *  `&host=` origin can only contain `https://` plus hostname characters, so the href
 *  contains no `<`/`>`/spaces that would break the angle-bracket form. */
export function buildEmbedMarkdown(
  origin: string,
  input: string,
  theme: BadgeTheme = 'light',
  hostHint?: string,
): string {
  const href = buildVerifyHref(origin, input, hostHint);
  const src = badgeAssetUrl(origin, theme);
  return `[![${BADGE_ALT}](${src})](<${href}>)`;
}
