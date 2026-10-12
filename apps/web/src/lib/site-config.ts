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
 * The specification's latest tagged revision, read from its front matter in
 * the civic-ai-tools repository at that tag. The link pins the tag, so the
 * text it opens is the version the site names. Move both together at the
 * next spec tag.
 */
export const SPECIFICATION = {
  version: "v0.1.10",
  url: "https://github.com/npstorey/civic-ai-tools/blob/v0.1.10-typed-standards-spec/docs/architecture/typed-standards-specification.md",
} as const;

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
