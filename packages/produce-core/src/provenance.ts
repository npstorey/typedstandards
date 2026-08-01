// Generic W3C PROV-O JSON-LD layer (spec §8.9) — types + assembly helpers.
//
// FORMAT ONLY. The graph WALKING — mapping an application's trace/span shape
// to entities and activities — and every domain concern (a domain namespace,
// an id scheme, an agent registry) belong to the caller. The core carries the
// JSON-LD shapes and the PROV wiring discipline (used / wasGeneratedBy /
// wasDerivedFrom / wasAssociatedWith), so any producer emits structurally
// identical graphs from its own capture.
//
// Byte discipline: object insertion order is preserved everywhere (the
// caller's `@context` map order is kept verbatim; node properties land after
// `@id`/`@type` in the order the caller supplies them), because pre-v0.1
// envelopes hash `JSON.stringify` output — insertion order is the byte
// contract there.

/** A node of the JSON-LD `@graph`: an id, one or more types, and open
 *  properties. */
export interface ProvNode {
  '@id': string;
  '@type': string | string[];
  [key: string]: unknown;
}

/** A PROV-O provenance graph in JSON-LD: a namespace `@context` plus the
 *  flat `@graph` node list. This is the shape the envelope's `provenance`
 *  field carries. */
export interface ProvGraph {
  '@context': Record<string, string>;
  '@graph': ProvNode[];
}

/** A by-id reference to another node — the value shape of every PROV edge. */
export interface ProvNodeRef {
  '@id': string;
}

// Well-known namespace URIs for callers assembling a context. The core never
// injects them — the caller's map is authoritative (including its order).
export const PROV_NS = 'http://www.w3.org/ns/prov#';
export const XSD_NS = 'http://www.w3.org/2001/XMLSchema#';
export const DCTERMS_NS = 'http://purl.org/dc/terms/';

/**
 * Build a JSON-LD `@context` from a caller-supplied namespace map
 * (prefix → namespace URI). The map is copied with its insertion order
 * preserved verbatim (legacy-chain byte discipline). A `prov` binding is
 * required — every helper below emits `prov:` terms.
 */
export function makeProvContext(
  namespaces: Record<string, string>,
): Record<string, string> {
  if (!('prov' in namespaces)) {
    throw new Error(
      "makeProvContext requires a 'prov' namespace binding (e.g. PROV_NS)",
    );
  }
  for (const [prefix, uri] of Object.entries(namespaces)) {
    if (!prefix || typeof uri !== 'string' || uri.length === 0) {
      throw new Error(`makeProvContext: invalid namespace binding "${prefix}"`);
    }
  }
  return { ...namespaces };
}

/** Assemble a graph object from a context and node list. */
export function makeProvGraph(
  context: Record<string, string>,
  nodes: ProvNode[],
): ProvGraph {
  return { '@context': context, '@graph': nodes };
}

/** Wrap a node id as a by-id reference. */
export function provRef(id: string): ProvNodeRef {
  return { '@id': id };
}

/** Construct a graph node: `@id`, `@type`, then the caller's properties in
 *  their supplied order. */
export function makeProvNode(
  id: string,
  type: string | string[],
  properties: Record<string, unknown> = {},
): ProvNode {
  return { '@id': id, '@type': type, ...properties };
}

/** A `prov:Entity` node (plus any additional types, e.g. `prov:Plan`). */
export function makeEntityNode(
  id: string,
  properties: Record<string, unknown> = {},
  additionalTypes: readonly string[] = [],
): ProvNode {
  return makeProvNode(
    id,
    additionalTypes.length > 0 ? ['prov:Entity', ...additionalTypes] : 'prov:Entity',
    properties,
  );
}

/** A `prov:Activity` node (plus any additional types). */
export function makeActivityNode(
  id: string,
  properties: Record<string, unknown> = {},
  additionalTypes: readonly string[] = [],
): ProvNode {
  return makeProvNode(
    id,
    additionalTypes.length > 0
      ? ['prov:Activity', ...additionalTypes]
      : 'prov:Activity',
    properties,
  );
}

/** A `prov:Agent` node (plus any additional types, e.g. `prov:SoftwareAgent`). */
export function makeAgentNode(
  id: string,
  properties: Record<string, unknown> = {},
  additionalTypes: readonly string[] = [],
): ProvNode {
  return makeProvNode(
    id,
    additionalTypes.length > 0 ? ['prov:Agent', ...additionalTypes] : 'prov:Agent',
    properties,
  );
}

// --- Edge builders (the PROV wiring discipline) ---
//
// Each returns a single-property object for spreading into a node's
// properties, so the caller controls property order:
//   makeActivityNode(id, { ...provWasAssociatedWith(agent), ...provUsed(inputs) })

/** `prov:used` — the entities an activity consumed. */
export function provUsed(
  ids: readonly string[],
): { 'prov:used': ProvNodeRef[] } {
  return { 'prov:used': ids.map(provRef) };
}

/** `prov:wasGeneratedBy` — the activity that produced an entity. */
export function provWasGeneratedBy(
  id: string,
): { 'prov:wasGeneratedBy': ProvNodeRef } {
  return { 'prov:wasGeneratedBy': provRef(id) };
}

/** `prov:wasDerivedFrom` — the entities an entity was derived from. */
export function provWasDerivedFrom(
  ids: readonly string[],
): { 'prov:wasDerivedFrom': ProvNodeRef[] } {
  return { 'prov:wasDerivedFrom': ids.map(provRef) };
}

/** `prov:wasAssociatedWith` — the agent responsible for an activity. */
export function provWasAssociatedWith(
  id: string,
): { 'prov:wasAssociatedWith': ProvNodeRef } {
  return { 'prov:wasAssociatedWith': provRef(id) };
}

/** An `xsd:dateTime` literal (for `prov:startedAtTime` / `prov:endedAtTime`). */
export function xsdDateTime(
  iso: string,
): { '@value': string; '@type': 'xsd:dateTime' } {
  return { '@value': iso, '@type': 'xsd:dateTime' };
}
