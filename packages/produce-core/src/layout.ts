// Layout node builder (spec §8.14, hub ADR-0034) — format-neutral, I/O-free,
// deterministic.
//
// A `content/layout/v1` node is a standalone assertion of how a host's page
// arranges a node's parts: the structural primitive (`metadata`, `type`,
// `signer`, `contentCanonicalization`, `contentHash`) plus the seven §8.14.1
// payload fields at the canonical-JSON top level. It carries no `targetNodeId`
// and no `output`. It is built in `buildAttestationNode`'s form: the content
// hash under legacy-json/v1 over the node minus `contentHash`, spread on last,
// and the nodeId the RFC 8785 JCS envelope hash, both from verify-core.
//
// The builder refuses a malformed payload before it is signed (ADR-0034 §E):
// verify-core runs no payload check on a layout (§8.14.5), so the field types
// of the §8.14.1 table are checked here, at runtime, top level and sub-members.
// Part names are not checked: the names in `order`, `disclosure.order` and
// `steps.placement`, and `rendererVersion` itself, are the renderer's
// vocabulary (§8.14.4), so any string passes.
//
// Determinism inputs (`packageId`, `createdAt`, `signingKeyId`) and the signer
// are caller-supplied — no RNG, no clock in the core.

// The URI is defined once in verify-core, which registers it for check #12;
// imported for the builder body and re-exported so a producer needs a single
// import.
import {
  CONTENT_LAYOUT,
  LEGACY_JSON_CANONICALIZATION,
  computeContentHashSha256,
  computeEnvelopeHash,
  type SignerIdentity,
} from '@typedstandards/verify-core';

export { CONTENT_LAYOUT };

const PACKAGE_SCHEMA_VERSION = '0.1.0';

/** `disclosure` (§8.14.1): the part that holds a node's detail behind a
 *  heading — the heading's text, the order of its sections, and whether it
 *  starts open. */
export interface LayoutDisclosure {
  label: string;
  order: string[];
  openByDefault: boolean;
}

/** `steps` (§8.14.1): the part that shows the run's steps — where it sits,
 *  and whether it starts open. */
export interface LayoutSteps {
  placement: string;
  openByDefault: boolean;
}

/** The seven §8.14.1 payload fields, in the order the node carries them. */
export interface LayoutPayload {
  /** The layout's name. */
  name: string;
  /** The layout's own version: an integer of at least 1. */
  version: number;
  /** The `metadata.contentProfile` values of the nodes the layout is for. */
  appliesTo: string[];
  /** The page's parts, in the order the page shows them; no entry repeated. */
  order: string[];
  disclosure: LayoutDisclosure;
  steps: LayoutSteps;
  /** The renderer contract the layout was written for. */
  rendererVersion: string;
}

/**
 * A `content/layout/v1` node (spec §8.14.2). `contentHash` is typed optional
 * only so the builder can compute it from the base object (a hash cannot
 * include itself); it is always present on a built node.
 */
export interface LayoutNode extends LayoutPayload {
  metadata: {
    schemaVersion: string;
    packageId: string;
    createdAt: string;
    signingKeyId: string;
  };
  /** Always `content/layout/v1`. */
  type: string;
  /** Envelope-side identity claim (spec §8.1.1, §8.5): any party with a
   *  `pseudonymous`-or-better binding, a host's platform key included. */
  signer: SignerIdentity;
  /** Always legacy-json/v1 (the whole-node-minus-contentHash rule). */
  contentCanonicalization: string;
  /** Multihash digest set fingerprinting the node (spec §8.2). */
  contentHash?: Record<string, string>;
}

export interface LayoutInput extends LayoutPayload {
  /** Deterministic envelope identity — caller-supplied (no RNG in the core). */
  packageId: string;
  /** Envelope timestamp (ISO 8601) — caller-supplied (no clock in the core). */
  createdAt: string;
  /** Key identifier recorded in `metadata.signingKeyId` — caller-supplied. */
  signingKeyId: string;
  signer: SignerIdentity;
}

const INPUT_MEMBERS: readonly string[] = [
  'packageId',
  'createdAt',
  'signingKeyId',
  'signer',
  'name',
  'version',
  'appliesTo',
  'order',
  'disclosure',
  'steps',
  'rendererVersion',
];
const DISCLOSURE_MEMBERS: readonly string[] = ['label', 'order', 'openByDefault'];
const STEPS_MEMBERS: readonly string[] = ['placement', 'openByDefault'];

function refuse(rule: string): never {
  throw new Error(`buildLayoutNode: ${rule}`);
}

function requirePresent(value: unknown, field: string): void {
  if (value === undefined) refuse(`${field} is required`);
}

function requireString(value: unknown, field: string): string {
  requirePresent(value, field);
  if (typeof value !== 'string') refuse(`${field} must be a string`);
  return value;
}

function requireBoolean(value: unknown, field: string): boolean {
  requirePresent(value, field);
  if (typeof value !== 'boolean') refuse(`${field} must be a boolean`);
  return value;
}

/** An array of strings, copied. Every index is read, so a sparse array's hole
 *  reads as a non-string entry rather than being skipped. */
function requireStringArray(value: unknown, field: string, nonEmpty: boolean): string[] {
  requirePresent(value, field);
  if (!Array.isArray(value)) refuse(`${field} must be an array of strings`);
  if (nonEmpty && value.length === 0) refuse(`${field} must not be empty`);
  const out: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const entry: unknown = value[i];
    if (typeof entry !== 'string') refuse(`${field}[${i}] must be a string`);
    out.push(entry);
  }
  return out;
}

function requireObject(
  value: unknown,
  field: string,
  members: readonly string[],
): Record<string, unknown> {
  requirePresent(value, field);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    refuse(`${field} must be an object`);
  }
  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!members.includes(key)) refuse(`${field} has a member outside §8.14.1: "${key}"`);
  }
  return obj;
}

/** Check the payload against the §8.14.1 table and return a copy of it, in
 *  the table's member order. Values are kept as supplied. */
function checkPayload(input: LayoutInput): LayoutPayload {
  const raw = input as unknown as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (!INPUT_MEMBERS.includes(key)) refuse(`input has a member outside §8.14.1: "${key}"`);
  }

  const name = requireString(raw['name'], 'name');

  const version = raw['version'];
  requirePresent(version, 'version');
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 1) {
    refuse('version must be an integer of at least 1');
  }

  const appliesTo = requireStringArray(raw['appliesTo'], 'appliesTo', true);

  const order = requireStringArray(raw['order'], 'order', true);
  const firstAt = new Map<string, number>();
  order.forEach((part, i) => {
    const first = firstAt.get(part);
    if (first !== undefined) {
      refuse(`order must not repeat an entry: "${part}" at ${first} and ${i}`);
    }
    firstAt.set(part, i);
  });

  const d = requireObject(raw['disclosure'], 'disclosure', DISCLOSURE_MEMBERS);
  const disclosure: LayoutDisclosure = {
    label: requireString(d['label'], 'disclosure.label'),
    order: requireStringArray(d['order'], 'disclosure.order', false),
    openByDefault: requireBoolean(d['openByDefault'], 'disclosure.openByDefault'),
  };

  const s = requireObject(raw['steps'], 'steps', STEPS_MEMBERS);
  const steps: LayoutSteps = {
    placement: requireString(s['placement'], 'steps.placement'),
    openByDefault: requireBoolean(s['openByDefault'], 'steps.openByDefault'),
  };

  const rendererVersion = requireString(raw['rendererVersion'], 'rendererVersion');

  return { name, version, appliesTo, order, disclosure, steps, rendererVersion };
}

/**
 * Build an unsigned `content/layout/v1` node and its nodeId.
 *
 * Throws an `Error` whose message starts `buildLayoutNode:` when the payload
 * does not meet the §8.14.1 table: a field missing or of the wrong type,
 * `version` not an integer of at least 1, an empty `appliesTo` or `order`, a
 * repeated `order` entry, or a member outside the table (at the top level of
 * the input, or in `disclosure` or `steps`). Part names are not checked.
 *
 * The off-log content hash is computed under legacy-json/v1 from the node
 * minus `contentHash`, then spread on last; the nodeId is the RFC 8785 JCS
 * envelope hash. Signing, timestamping and storage are caller steps. An
 * unsigned node is a complete, first-class result.
 */
export function buildLayoutNode(input: LayoutInput): { node: LayoutNode; nodeId: string } {
  const payload = checkPayload(input);

  const base: LayoutNode = {
    metadata: {
      schemaVersion: PACKAGE_SCHEMA_VERSION,
      packageId: input.packageId,
      createdAt: input.createdAt,
      signingKeyId: input.signingKeyId,
    },
    type: CONTENT_LAYOUT,
    signer: input.signer,
    contentCanonicalization: LEGACY_JSON_CANONICALIZATION,
    name: payload.name,
    version: payload.version,
    appliesTo: payload.appliesTo,
    order: payload.order,
    disclosure: payload.disclosure,
    steps: payload.steps,
    rendererVersion: payload.rendererVersion,
  };

  const contentHash = {
    sha256: computeContentHashSha256(
      base as unknown as Record<string, unknown>,
      LEGACY_JSON_CANONICALIZATION,
    ),
  };
  const node: LayoutNode = { ...base, contentHash };
  const nodeId = computeEnvelopeHash(node as unknown as Record<string, unknown>);

  return { node, nodeId };
}
