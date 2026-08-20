// Envelope assembly for `content/*` nodes (spec §8.1, §8.1.1, §8.2) —
// format-neutral, I/O-free, deterministic.
//
// This is the producer counterpart of verify-core's §9.2 recompute chain: the
// envelope is assembled here and hashed with the SAME `computeEnvelopeHash` /
// `computeContentHashSha256` the verifier uses, so producer and verifier agree
// on one hash by construction.
//
// The format/domain line: the core never DERIVES envelope values — the caller
// (an application harness, or a prospective adopter's pipeline) derives
// `queries`, `dataSources`, `skillMetadata`, `provenance`, `producerProfile`,
// `contentCanonicalization`, `summary`, and `extensions`, and the core spreads
// them into the envelope under the exact conditional rules of the reference
// assembly — byte-identical canonical JSON for equivalent inputs, on both the
// legacy `JSON.stringify` chain and the v0.1 RFC 8785 JCS chain.
// `captureMethod` / `contentProfile` / `producerProfile` are OPAQUE strings
// here: their vocabulary is profile-governed (spec §8.6), not core-encoded.
//
// Determinism: no clock, no RNG. `packageId`, `createdAt`, and `signingKeyId`
// are caller-supplied inputs — which is what makes byte-golden fixture tests
// possible.
//
// Signing status is explicit (a first-class unsigned tier): `buildEnvelope`
// returns a COMPLETE package and its envelope hash with no signature. Signing
// is a separate, caller-invoked step (`signEnvelopeHash`); nothing in this
// package labels an unsigned result as anything else.

import {
  LEGACY_JSON_CANONICALIZATION,
  computeContentHashSha256,
  computeEnvelopeHash,
  sha256Hex,
  type BlobRef,
  type SignerIdentity,
} from '@typedstandards/verify-core';
import type { ProvGraph } from './provenance.ts';

const PACKAGE_SCHEMA_VERSION = '0.1.0';

// Two-family node type taxonomy (spec §8.1.1, §8.12): every node carries
// `type` of the form `content/<noun>/v<N>` or `attestation/<verb>/v<N>`.
// Analysis output defaults to `content/analysis/v1`; pre-v0.1 packages omit
// the field and are interpreted as this value.
export const DEFAULT_CONTENT_TYPE = 'content/analysis/v1';

/**
 * One entry of the envelope's `queries` array (spec §8.1). Envelope-ready:
 * the caller derives entries from its own tool-call capture, including
 * `operationType` — the core carries no derivation table and no fallback.
 */
export interface EnvelopeQuery {
  tool: string;
  operationType: string;
  arguments: Record<string, unknown>;
  datasetId?: string;
  portal?: string;
  duration_ms?: number;
  resultRows?: number;
  resultColumns?: number;
}

/**
 * One entry of the envelope's `dataSources` array (spec §8.1): a stable
 * source identifier plus catalog/portal coordinates. POPULATION (walking a
 * trace, consulting a source registry) is caller work — the core carries the
 * field type only.
 */
export interface DataSourceEntry {
  sourceId: string;
  catalogType: string;
  portalUrl: string;
  /** Per-dataset id. Absent for sources without a dataset-keyed surface. */
  datasetId?: string;
  /** Canonical per-dataset URL. Absent for sources without one. */
  datasetUrl?: string;
  accessTimestamp: string;
}

/** The envelope's `cost` block. Fully caller-supplied (including any
 *  `totalTokens` roll-up); the core re-emits the fields in the envelope's
 *  fixed key order. */
export interface EnvelopeCost {
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
  model: string;
  durationMs?: number;
}

/** The envelope's `skillMetadata` block. Extraction from a trace is caller
 *  work; `skillText` may be a BlobRef for very large composed skills. */
export interface SkillMetadata {
  systemPromptHash?: string;
  mcpServerUrl?: string;
  skillText?: string | BlobRef;
}

/**
 * Input to `buildEnvelope` — the format-shaped package input. Every value is
 * caller-supplied data; none is derived, defaulted from an environment, or
 * read from a clock inside the core.
 */
export interface EnvelopeInput {
  /** Deterministic envelope identity — caller-supplied (no RNG in the core). */
  packageId: string;
  /** Envelope timestamp (ISO 8601) — caller-supplied (no clock in the core). */
  createdAt: string;
  /** Key identifier recorded in `metadata.signingKeyId` and covered by the
   *  envelope hash (defense against post-hoc registry relabeling). Caller-
   *  supplied; there is no active-key probe in the core. */
  signingKeyId: string;
  prompt: string;
  promptVisibility: 'full_text' | 'hash_only';
  queries: EnvelopeQuery[];
  dataSources: DataSourceEntry[];
  cost: EnvelopeCost;
  skillMetadata: SkillMetadata;
  /** Assistant output text OR a BlobRef pointing at it. Passed through
   *  unchanged — the package commits to the reference object. */
  output: string | BlobRef;
  /** Trace object OR a BlobRef pointing at the same content stored out of
   *  band. Passed through unchanged; the core never inspects spans. */
  trace: Record<string, unknown> | BlobRef;
  /** Emitted into canonical JSON when supplied (and thereby covered by the
   *  envelope hash). Whether a content profile REQUIRES the summary in
   *  canonical JSON is the caller's rule, not the core's. */
  summary?: string;
  /** Capture-method label (spec §8.6). Opaque string; conditional-spread so
   *  inputs without it stay byte-identical to the pre-label shape. */
  captureMethod?: string;
  /** Content-profile label (spec §8.6). Opaque string; absence is treated as
   *  the default profile by verifiers. */
  contentProfile?: string;
  /** Producer Profile compound `<profile-type>/<profile-subtype>` label
   *  (spec §8.1.1, §8.6). Opaque string; any auto-derivation from a content
   *  profile is caller work. */
  producerProfile?: string;
  /** Node type per the two-family taxonomy (spec §8.1.1, §8.12). Its
   *  presence is the v0.1 discriminator (spec §8.2): it switches the envelope
   *  onto the JCS chain and triggers `contentCanonicalization` +
   *  `contentHash` emission. Absence keeps the legacy chain byte-identical. */
  type?: string;
  /** Envelope-side identity claim (spec §8.1.1, §8.5). Emitted verbatim. */
  signer?: SignerIdentity;
  /** Content-canonicalization rule URI (spec §8.2). Caller-selected; defaults
   *  to legacy-json/v1. Emitted only on v0.1 envelopes. */
  contentCanonicalization?: string;
  /** Finished PROV-O graph (spec §8.9). Graph construction is caller work —
   *  see `provenance.ts` for the generic helpers. */
  provenance?: ProvGraph;
  /** Implementation-specific artifacts keyed by reverse-DNS identifier.
   *  Included in canonical JSON (and so covered by the envelope hash) only
   *  when non-empty. */
  extensions?: Record<string, unknown>;
}

/**
 * A conformant `content/*` record-package envelope (spec §8.1). Field order in
 * this type mirrors emission order, which on the legacy chain IS the byte
 * contract (`JSON.stringify` preserves insertion order).
 *
 * Named `EvidencePackage` before the 2026-08-19 vocabulary settlement; that
 * name is still exported as a deprecated alias of this type (see below).
 */
export interface RecordPackage {
  metadata: {
    schemaVersion: string;
    packageId: string;
    createdAt: string;
    /** Key identifier that signed this package — covered by the envelope
     *  hash; verifiers cross-check it against the signature envelope's kid. */
    signingKeyId: string;
    /** Capture-method label. Present only when supplied; covered by the
     *  envelope hash when present. */
    captureMethod?: string;
    /** Content-profile label. Present only when supplied; absence is treated
     *  as the default profile. */
    contentProfile?: string;
  };
  /** Producer Profile label (spec §8.1.1). Top-level envelope field (parallel
   *  axis to `metadata.contentProfile`, the grandfathered legacy alias). */
  producerProfile?: string;
  /** Node type (spec §8.1.1, §8.12). Absence is interpreted as
   *  `content/analysis/v1`. */
  type?: string;
  /** Envelope-side identity claim (spec §8.1.1, §8.5). Distinct from the
   *  signature envelope; verifiers cross-check the two via the trust
   *  registry. */
  signer?: SignerIdentity;
  /** Content-canonicalization rule URI (spec §8.1.1, §8.2). Emitted on v0.1
   *  packages; absent on pre-v0.1 packages. */
  contentCanonicalization?: string;
  /** Multihash content-hash digest set (spec §8.1.1, §8.2), keyed by
   *  lowercase algorithm name. Its presence as a multihash object is the §8.2
   *  detection signal routing a package to the JCS chain. */
  contentHash?: Record<string, string>;
  prompt: {
    hash: string;
    visibility: 'full_text' | 'hash_only';
    text?: string;
  };
  queries: EnvelopeQuery[];
  dataSources: DataSourceEntry[];
  cost: EnvelopeCost;
  skillMetadata: SkillMetadata;
  /** Assistant output — inline text or a BlobRef. */
  output: string | BlobRef;
  /** Trace, either inline or referenced by hash. */
  trace: Record<string, unknown> | BlobRef;
  /** Short, citation-ready summary. When present in canonical JSON it is
   *  covered by the envelope hash. */
  summary?: string;
  provenance?: ProvGraph;
  /** Implementation-specific artifacts, keyed by reverse-DNS identifier.
   *  Core consumers MUST NOT require any particular extension. */
  extensions?: Record<string, unknown>;
}

/**
 * @deprecated Renamed to {@link RecordPackage} in the 2026-08-19 vocabulary
 * settlement — "evidence" is retired from the artifact/infrastructure brand
 * role and retained only for the epistemic Question/Evidence/Claim role (spec
 * §6.3, Appendix J; migration class `alias-and-deprecate`).
 *
 * A pure type alias, so the two names are interchangeable in every position
 * and no consumer typed against the old name has to change. The alias is
 * removed no earlier than this package's next MAJOR version. New code should
 * use `RecordPackage`.
 */
export type EvidencePackage = RecordPackage;

/** Compile-time guard for the alias above (spec Appendix J requires the old
 *  name to keep working, not merely to exist). Both directions are asserted,
 *  so narrowing either name to a subset of the other fails `tsc` here rather
 *  than in a consumer's build. Type-only — erases entirely at emit. */
type AssertTrue<T extends true> = T;
type _EvidencePackageAliasHolds = AssertTrue<
  EvidencePackage extends RecordPackage
    ? RecordPackage extends EvidencePackage
      ? true
      : false
    : false
>;

/**
 * Assemble a structured record package from caller-supplied data. Returns
 * the package object and its envelope hash (spec §8.2) — and NO signature:
 * an unsigned envelope is a complete, first-class result.
 *
 * BlobRef fields (`trace`, `output`, `skillMetadata.skillText`) are passed
 * through unchanged; the core never downloads them, so the package commits to
 * the reference object while the content stays wherever the caller stored it.
 *
 * Byte-compat discipline (the refactor-safety bar): conditional spreads keep
 * inputs that omit optional labels byte-identical to the pre-label envelope
 * shape; `contentHash` is computed from the base object and spread on LAST
 * (a hash cannot include itself); the envelope hash routes by the §8.2
 * detection rule via verify-core's shared `computeEnvelopeHash`.
 */
export function buildEnvelope(
  input: EnvelopeInput,
): { pkg: RecordPackage; envelopeHash: string } {
  const promptHash = sha256Hex(input.prompt);

  // Re-emit caller-supplied query entries in the envelope's fixed key order.
  // On the legacy chain the envelope hash is SHA-256(JSON.stringify(pkg)) —
  // insertion order IS the byte contract — so entries are rebuilt literally
  // rather than spread through (this also drops any extra caller keys).
  const queries = input.queries.map((q) => ({
    tool: q.tool,
    operationType: q.operationType,
    arguments: q.arguments,
    datasetId: q.datasetId,
    portal: q.portal,
    duration_ms: q.duration_ms,
    resultRows: q.resultRows,
    resultColumns: q.resultColumns,
  }));

  // v0.1 discriminator (spec §8.2): the presence of `type` signals a v0.1
  // envelope and is what triggers `contentCanonicalization` + `contentHash`
  // emission and RFC 8785 JCS hashing. Callers that omit `type` keep the
  // legacy shape — no contentHash, `JSON.stringify` hashing — byte-identical.
  const isV01Envelope = input.type !== undefined;
  const contentCanonicalization =
    input.contentCanonicalization ?? LEGACY_JSON_CANONICALIZATION;

  const pkgBase: RecordPackage = {
    metadata: {
      schemaVersion: PACKAGE_SCHEMA_VERSION,
      packageId: input.packageId,
      createdAt: input.createdAt,
      signingKeyId: input.signingKeyId,
      // Conditional spread so inputs without captureMethod produce canonical
      // JSON identical to the pre-label shape (and therefore identical
      // hashes). Enforcing presence is a caller/route-layer rule.
      ...(input.captureMethod ? { captureMethod: input.captureMethod } : {}),
      // contentProfile is optional; absence means the default profile. Only
      // emitted into canonical JSON when explicitly set so inputs that never
      // supply it stay byte-identical.
      ...(input.contentProfile ? { contentProfile: input.contentProfile } : {}),
    },
    // Top-level envelope fields (spec §8.1.1). Conditional spread so
    // existing-shape inputs (no producerProfile/type/signer) emit
    // byte-identical canonical JSON; default-filling is caller work.
    ...(input.producerProfile ? { producerProfile: input.producerProfile } : {}),
    ...(input.type ? { type: input.type } : {}),
    ...(input.signer ? { signer: input.signer } : {}),
    // v0.1 content-canonicalization rule URI (spec §8.2), gated on the v0.1
    // discriminator so pre-v0.1 callers stay byte-identical. `contentHash` is
    // computed from this base object below and spread on last — it cannot be
    // in this literal because legacy-json/v1 fingerprints the package minus
    // contentHash (a hash cannot include itself).
    ...(isV01Envelope ? { contentCanonicalization } : {}),
    prompt: {
      hash: promptHash,
      visibility: input.promptVisibility,
      ...(input.promptVisibility === 'full_text' ? { text: input.prompt } : {}),
    },
    queries,
    dataSources: input.dataSources,
    cost: {
      promptTokens: input.cost.promptTokens,
      completionTokens: input.cost.completionTokens,
      totalTokens: input.cost.totalTokens,
      model: input.cost.model,
      durationMs: input.cost.durationMs,
    },
    skillMetadata: {
      systemPromptHash: input.skillMetadata.systemPromptHash,
      mcpServerUrl: input.skillMetadata.mcpServerUrl,
      skillText: input.skillMetadata.skillText,
    },
    output: input.output,
    trace: input.trace,
    // Emitted only when the caller supplies it (whether a profile REQUIRES
    // the summary in canonical JSON is the caller's gate), preserving
    // byte-identical canonical JSON for inputs that keep it off-envelope.
    ...(input.summary ? { summary: input.summary } : {}),
    ...(input.provenance ? { provenance: input.provenance } : {}),
    // Caller-supplied extensions (any auto-emitted extension is layered in by
    // the caller BEFORE assembly). Omitted entirely when empty, preserving
    // the canonical JSON of extension-less packages.
    ...(input.extensions && Object.keys(input.extensions).length > 0
      ? { extensions: input.extensions }
      : {}),
  };

  // v0.1 packages embed the multihash `contentHash` fingerprinting the
  // off-log content (spec §8.2). It is computed from `pkgBase` (which already
  // carries `contentCanonicalization` but not yet `contentHash`) and spread
  // on last; legacy callers leave `pkgBase` untouched so their canonical JSON
  // is byte-identical to the pre-v0.1 shape.
  const pkg: RecordPackage = isV01Envelope
    ? {
        ...pkgBase,
        contentHash: {
          sha256: computeContentHashSha256(
            pkgBase as unknown as Record<string, unknown>,
            contentCanonicalization,
          ),
        },
      }
    : pkgBase;

  // Envelope hash routes by the §8.2 detection rule: SHA-256(JCS) for v0.1
  // packages (multihash contentHash present), legacy SHA-256(JSON.stringify)
  // for pre-v0.1. Shared with verify-core so producer and verifier agree.
  const envelopeHash = computeEnvelopeHash(
    pkg as unknown as Record<string, unknown>,
  );

  return { pkg, envelopeHash };
}
