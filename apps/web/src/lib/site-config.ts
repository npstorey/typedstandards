/**
 * Site-wide config constants for typedstandards.org.
 */

/**
 * Where every contact / express-interest entry point on the site routes
 * (landing page and footer both read from here).
 *
 * Swap point: when a project inbox exists, change this ONE constant and every
 * entry point re-routes — no other edit needed. See the "Contact routing"
 * note in the repo README.
 */
export const EXPRESS_INTEREST_URL = "https://nathanstorey.com/contact/";

/**
 * Optional acknowledgment sentence for the /roadmap colophon.
 *
 * Approved wording arrives from the comms side — do not draft or guess it
 * here. When it lands, it is additive to the personal-project framing in the
 * colophon, never a replacement for it. While null, the colophon renders
 * exactly as it does today.
 */
export const SPONSOR_LINE: {
  /** Sentence text before the linked name (keep the trailing space). */
  prefix: string;
  /** The linked name, exactly as it should render. */
  linkText: string;
  linkHref: string;
  /** Sentence text after the link (usually just the closing period). */
  suffix: string;
} | null = {
  prefix: "Fiscally sponsored by ",
  linkText: "Metagov",
  linkHref: "https://metagov.org",
  suffix: ".",
};
