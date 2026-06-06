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
 *  verdict, consistent with the honesty constraint. */
export const BADGE_ALT = 'Verify this evidence with Typed Standards';

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
  return 'hash'; // 64-hex hash OR an evidence slug — both resolve by identifier
}

/** Build the verifier deep-link for a package input. A hosted URL goes through
 *  `?url=` (host-independent — works for any publisher, resolved by the verifier's
 *  deriveCommitmentUrl); a bare hash/slug uses the `?hash=` shorthand (resolved
 *  against the default host). `origin` is `''` for a same-origin (relative) link. */
export function buildVerifyHref(origin: string, input: string): string {
  const s = input.trim();
  const param = classifyBadgeInput(s) === 'url' ? 'url' : 'hash';
  return `${origin}/verify?${param}=${encodeURIComponent(s)}`;
}

/** Full badge asset URL for the given origin + theme. */
export function badgeAssetUrl(origin: string, theme: BadgeTheme = 'light'): string {
  return `${origin}${BADGE_ASSET_PATH}${theme === 'dark' ? '?theme=dark' : ''}`;
}

/** The copy-paste HTML embed: an `<a>` (deep-link) wrapping the badge `<img>`. */
export function buildEmbedHtml(origin: string, input: string, theme: BadgeTheme = 'light'): string {
  const href = buildVerifyHref(origin, input);
  const src = badgeAssetUrl(origin, theme);
  return `<a href="${href}">
  <img src="${src}" alt="${BADGE_ALT}" width="${BADGE_WIDTH}" height="${BADGE_HEIGHT}" />
</a>`;
}

/** The copy-paste Markdown embed (linked image). */
export function buildEmbedMarkdown(origin: string, input: string, theme: BadgeTheme = 'light'): string {
  const href = buildVerifyHref(origin, input);
  const src = badgeAssetUrl(origin, theme);
  return `[![${BADGE_ALT}](${src})](${href})`;
}
