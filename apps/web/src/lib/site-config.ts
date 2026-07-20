/**
 * Site-wide config constants for typedstandards.org.
 */

/**
 * Where every contact / express-interest entry point on the site routes
 * (header nav, footer, and landing page all read from here).
 *
 * Single swap point: change this ONE constant and every entry point
 * re-routes — no other edit needed. See the "Contact routing" note in the
 * repo README.
 */
export const EXPRESS_INTEREST_URL = "mailto:civicaitools@metagov.org";

/**
 * Optional sponsor / acknowledgment line rendered in the global site footer,
 * once per page.
 *
 * Approved wording arrives from the comms side — do not draft or guess it
 * here. It is additive to the personal-project framing in the footer, never a
 * replacement for it. While null, the footer renders exactly as it does today.
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
