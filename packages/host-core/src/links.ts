// Verifier links and badge snippets (typedstandards#125 G0 D14). STUB: the typed
// surface lands first so the links test links.

import type { HostIndex } from './served.ts';

export type BadgeTheme = 'light' | 'dark';

export interface RecordLinks {
  name: string;
  /** Where the bundle is served. */
  url: string;
  /** The verifier deep link, `…/verify?url=<percent-encoded url>`. */
  verify: string;
  html: string;
  markdown: string;
}

export function linksFor(index: HostIndex, theme: BadgeTheme = 'light'): RecordLinks[] {
  void index;
  void theme;
  return [];
}
