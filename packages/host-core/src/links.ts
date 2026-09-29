// Verifier links and badge snippets (typedstandards#125 G0 D14), in typedstandards.org's
// own form: the `?url=` value is percent-encoded.
//
// COPIED from apps/web/src/lib/badge-asset.ts at 41c43c9: the constants (:21-45),
// `classifyBadgeInput` (:82-90), `buildVerifyHref` (:121), `badgeAssetUrl` (:130),
// `buildEmbedHtml` (:143) and `buildEmbedMarkdown` (:162), with their bodies
// unchanged; `renderBadgeSvg` is not copied, since no snippet uses it. The site's
// file keeps the reasoning (the honesty constraint: the badge is a call to action,
// not a verdict; why the `&host=` hint is unencoded; why the Markdown destination is
// in angle brackets). The test compares this module's output with a golden captured
// from the site's own functions, so a drift between the copies fails it.

import type { HostIndex } from './served.ts';

/** The canonical production origin: a snippet always points at the real verifier. */
export const CANONICAL_ORIGIN = 'https://typedstandards.org';

/** Stable, CORS-fetchable path of the badge asset. `?theme=dark` selects the dark variant. */
export const BADGE_ASSET_PATH = '/badge/typed-standards-verify.svg';

/** Intrinsic badge dimensions (also the embed `<img>` width and height). */
export const BADGE_WIDTH = 248;
export const BADGE_HEIGHT = 30;

export type BadgeTheme = 'light' | 'dark';

/** Alt text for the embed `<img>`: it describes the action, not a verdict. */
export const BADGE_ALT = 'Verify this record with Typed Standards';

/** Classify a badge input. `bundle` (pasted JSON) is unsupported. */
export type BadgeInputKind = 'url' | 'hash' | 'bundle' | 'empty';

export function classifyBadgeInput(raw: string): BadgeInputKind {
  const s = raw.trim();
  if (!s) return 'empty';
  if (s.startsWith('{')) return 'bundle';
  if (/^https?:\/\//i.test(s)) return 'url';
  return 'hash'; // 64-hex hash OR a record slug — both resolve by identifier
}

/** The verifier deep link: a hosted URL goes through `?url=`, a bare hash or slug through `?hash=`. */
export function buildVerifyHref(origin: string, input: string, hostHint?: string): string {
  const s = input.trim();
  const kind = classifyBadgeInput(s);
  const param = kind === 'url' ? 'url' : 'hash';
  const hint = kind === 'hash' && hostHint ? `&host=${hostHint}` : '';
  return `${origin}/verify?${param}=${encodeURIComponent(s)}${hint}`;
}

/** Full badge asset URL for the given origin and theme. */
export function badgeAssetUrl(origin: string, theme: BadgeTheme = 'light'): string {
  return `${origin}${BADGE_ASSET_PATH}${theme === 'dark' ? '?theme=dark' : ''}`;
}

/** The copy-paste HTML embed: an `<a>` (the deep link) wrapping the badge `<img>`. */
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

/** The copy-paste Markdown embed (a linked image), the destination in angle brackets. */
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

// --- host-core's own part --------------------------------------------------

export interface RecordLinks {
  name: string;
  /** Where the bundle is served: the index's host plus a relative bundle path, or the bundle's absolute URL. */
  url: string;
  /** The verifier deep link, `https://typedstandards.org/verify?url=<percent-encoded url>`. */
  verify: string;
  html: string;
  markdown: string;
}

/** Each served record's verifier link and badge snippets, in the index's order. */
export function linksFor(index: HostIndex, theme: BadgeTheme = 'light'): RecordLinks[] {
  return index.records.map((r) => {
    const url = /^https?:\/\//i.test(r.bundle) ? r.bundle : `${index.host}${r.bundle}`;
    return {
      name: r.name,
      url,
      verify: buildVerifyHref(CANONICAL_ORIGIN, url),
      html: buildEmbedHtml(CANONICAL_ORIGIN, url, theme),
      markdown: buildEmbedMarkdown(CANONICAL_ORIGIN, url, theme),
    };
  });
}
