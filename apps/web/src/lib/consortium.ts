// Consortium membership data for the /consortium page.
//
// Membership is cleared for publication and mirrors the canonical roster on
// civicaitools.org. Members land as a pure data swap in this array — the page
// renders whatever is here and needs no other changes. A member card renders
// only with a complete package (blurb + logo + naming approval + link + role);
// entries with null logoSrc/url degrade gracefully.

export interface ConsortiumMember {
  /** Organization or program name. */
  name: string;
  /** One-to-two sentence description of the member and its role. */
  blurb: string;
  /** Path to a logo image under /public, or null to render a neutral block. */
  logoSrc: string | null;
  /** Member's own site, or null if none should be linked. */
  url: string | null;
  /** Short role label, e.g. "Founding member". */
  role: string;
}

export const CONSORTIUM_MEMBERS: ConsortiumMember[] = [
  {
    name: "Metagov",
    blurb:
      "Metagov is a laboratory for digital governance, cultivating tools, practices, and communities that enable self-governance in the digital age. Provides fiscal sponsorship for Civic AI Tools and Typed Standards.",
    logoSrc: "/consortium/metagov-logofull-dark.png",
    url: "https://metagov.org",
    role: "Fiscal sponsor",
  },
  {
    name: "Dynamical Systems Group",
    blurb:
      "Dynamical Systems Group brings systems-engineering rigor to the standard — ontology assembly, verification and validation, and document-assurance practice. Lead external technical advisor to the Typed Standards protocol.",
    logoSrc: "/consortium/dynamical-systems-lockup-copper.png",
    url: "https://www.dynamicalsystemsgroup.com",
    role: "Founding member",
  },
  {
    name: "datHere",
    blurb:
      "datHere builds AI-Ready open source, standards-based Data Infrastructure; its Verikan Data Concierge is the first publisher in the Typed Standards host directory.",
    logoSrc: "/consortium/logo-datHere-light.png",
    url: "https://dathere.com",
    role: "Founding member",
  },
];
