// The host build (typedstandards#125 G0 D1, D2, D6, D12): from what the CLI's `sign`
// and `withdraw` printed, the bundles, the key registry and the index a static host
// serves. Pure: the inputs arrive as an in-memory file map keyed by their paths
// relative to host.json, and the outputs leave as one keyed by served path.
//
// A bundle is produce-core's `buildCommitmentView` over the signed document, plus the
// registry copy when a registry is served, plus the package:
//   { ...view, trustRegistry, package }  or  { ...view, package }.
// It carries no `lifecycle` summary in 0.1.0 (G0 D2): adding one later is a
// host-core minor and a rebuild of the bundles, with no re-signing. The index, the
// display seam and the verifier already read status from the carried attestations.
//
// Derived from the worked example's host stages (package/build.mjs at b40c30f:
// registryFor, bundleFor, recordsJsonFor), with the example-specific parts left out.

import { buildCommitmentView, type SignerIdentity } from '@typedstandards/produce-core';
import { validateRegistry } from '@typedstandards/verify-core';
import { HostError, isObject, parseJsonFile, serialize, utf8, type FileMap, type JsonObject } from './json.ts';
import { parseManifest, type HostManifest } from './manifest.ts';
import { normalizePath } from './paths.ts';
import { checkCarriedNode, checkSignedDocument, indexLifecycleOf, lifecycleOf, signerOf, type CarriedNode, type SignedDocument } from './records.ts';
import { INDEX_PATH, REGISTRY_PATH, bundlePathOf, type HostIndex, type IndexRecord } from './served.ts';

export interface RegistryDocument {
  $comment?: string;
  keys: Array<Record<string, unknown>>;
}

export interface HostBuild {
  /** Served path (relative to the served directory) to bytes. */
  files: Map<string, Uint8Array>;
  index: HostIndex;
  registry: RegistryDocument | null;
}

interface Loaded {
  name: string;
  title: string;
  extensions?: JsonObject;
  signed: SignedDocument;
  carried: CarriedNode[];
}

function readInput(files: FileMap, path: string, where: string): unknown {
  const bytes = files.get(normalizePath(path));
  if (bytes === undefined) throw new HostError(`${where}: ${path} was not found`);
  return parseJsonFile(bytes, `${where}: ${path}`);
}

function load(manifest: HostManifest, files: FileMap): Loaded[] {
  const seen = new Map<string, string>();
  return manifest.records.map((r) => {
    const where = `record ${r.name}`;
    const signed = checkSignedDocument(readInput(files, r.signed, where), `${where}: ${r.signed}`);
    const other = seen.get(signed.envelopeHash);
    if (other !== undefined) throw new HostError(`${where}: ${r.signed} is the record ${other} already serves (envelopeHash ${signed.envelopeHash})`);
    seen.set(signed.envelopeHash, r.name);
    const carried = r.attestations.map((path) => {
      const node = checkCarriedNode(readInput(files, path, where), `${where}: ${path}`);
      if (node.node['targetNodeId'] !== signed.envelopeHash) {
        throw new HostError(`${where}: ${path} targets ${String(node.node['targetNodeId'])}, not this record (${signed.envelopeHash})`);
      }
      return node;
    });
    return { name: r.name, title: r.title, ...(r.extensions ? { extensions: r.extensions } : {}), signed, carried };
  });
}

/**
 * The registry a host serves (G0 D12): one key, which every record under it must
 * be signed with. Its `kid` is the signer's identifier, and it is active from the
 * earliest `createdAt` among the records it covers.
 */
function registryFor(manifest: HostManifest, records: Loaded[]): RegistryDocument | null {
  if (manifest.registry === null) return null;
  const first = records[0];
  const signer = signerOf(first.signed.package);
  if (!signer || typeof signer['identifier'] !== 'string') throw new HostError(`record ${first.name}: the package names no signer identifier`);
  const identity = { bindingTier: signer['bindingTier'], identifier: signer['identifier'], displayName: signer['displayName'] };
  for (const r of records) {
    const s = signerOf(r.signed.package);
    const same = s && s['identifier'] === identity.identifier && s['bindingTier'] === identity.bindingTier && s['displayName'] === identity.displayName;
    if (!same || r.signed.signature.publicKey !== first.signed.signature.publicKey) {
      throw new HostError(`record ${r.name}: its signer or signing key differs from record ${first.name}'s; in 0.1.0 every record under a registry has one signer`);
    }
    if (r.signed.signature.kid !== undefined && r.signed.signature.kid !== identity.identifier) {
      throw new HostError(`record ${r.name}: its signature's kid ${r.signed.signature.kid} is not the signer's identifier ${identity.identifier}, which the registry lists the key under`);
    }
  }
  const createdAt = records.map((r) => {
    const at = isObject(r.signed.package['metadata']) ? r.signed.package['metadata']['createdAt'] : undefined;
    if (typeof at !== 'string' || at === '') throw new HostError(`record ${r.name}: the package has no metadata.createdAt`);
    return at;
  });
  const activatedAt = createdAt.reduce((a, b) => (b < a ? b : a));
  const registry: RegistryDocument = {
    ...(manifest.registry.$comment !== undefined ? { $comment: manifest.registry.$comment } : {}),
    keys: [
      {
        kid: identity.identifier,
        publicKey: first.signed.signature.publicKey,
        status: 'active',
        activatedAt,
        deprecatedAt: null,
        revokedAt: null,
        signerIdentity: identity,
      },
    ],
  };
  if (!validateRegistry(registry)) throw new HostError('the registry host-core built does not validate under verify-core');
  return registry;
}

const optionalString = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

function bundleFor(r: Loaded, manifest: HostManifest, registry: RegistryDocument | null, trustRegistryUrl: string | undefined): JsonObject {
  const pkg = r.signed.package;
  const metadata = isObject(pkg['metadata']) ? pkg['metadata'] : {};
  let view: Record<string, unknown>;
  try {
    view = buildCommitmentView({
      packageHash: r.signed.envelopeHash,
      visibility: manifest.visibility,
      captureMethod: optionalString(metadata['captureMethod']) ?? null,
      contentProfile: optionalString(metadata['contentProfile']) ?? null,
      producerProfile: optionalString(pkg['producerProfile']),
      type: optionalString(pkg['type']),
      signer: signerOf(pkg) as SignerIdentity | undefined,
      contentHash: isObject(pkg['contentHash']) ? (pkg['contentHash'] as Record<string, string>) : undefined,
      contentCanonicalization: optionalString(pkg['contentCanonicalization']),
      signature: { ...r.signed.signature },
      lifecycleAttestations: r.carried,
      ...(trustRegistryUrl !== undefined ? { trustRegistryUrl } : {}),
      subjectTitle: r.title,
      subjectSummary: optionalString(pkg['summary']) ?? null,
    });
  } catch (err) {
    throw new HostError(`record ${r.name}: produce-core refused the view: ${(err as Error).message}`);
  }
  return registry ? { ...view, trustRegistry: registry, package: pkg } : { ...view, package: pkg };
}

function indexRecordFor(r: Loaded): IndexRecord {
  const pkg = r.signed.package;
  const metadata = isObject(pkg['metadata']) ? pkg['metadata'] : {};
  const life = lifecycleOf(r.carried, r.signed.envelopeHash, pkg, r.signed.signature);
  return {
    name: r.name,
    bundle: bundlePathOf(r.name),
    packageHash: r.signed.envelopeHash,
    createdAt: optionalString(metadata['createdAt']) ?? '',
    type: optionalString(pkg['type']) ?? '',
    signer: optionalString(signerOf(pkg)?.['identifier']) ?? '',
    ...indexLifecycleOf(life),
    ...(r.extensions ? { extensions: r.extensions } : {}),
  };
}

/**
 * Build what a host serves from a parsed `host.json` and the files it names, keyed
 * by their paths relative to the manifest. Throws `HostError` on an input it
 * refuses; writes nothing.
 */
export function buildHost(manifest: unknown, files: FileMap): HostBuild {
  const m = parseManifest(manifest);
  const normalized = new Map([...files].map(([k, v]) => [normalizePath(k), v]));
  const records = load(m, normalized);
  const registry = registryFor(m, records);
  const trustRegistryUrl = registry ? `${m.origin}/${REGISTRY_PATH}` : undefined;
  const out = new Map<string, Uint8Array>();
  for (const r of records) out.set(bundlePathOf(r.name), utf8(serialize(bundleFor(r, m, registry, trustRegistryUrl))));
  if (registry) out.set(REGISTRY_PATH, utf8(serialize(registry)));
  const index: HostIndex = {
    version: 1,
    ...(m.index.$comment !== undefined ? { $comment: m.index.$comment } : {}),
    host: `${m.origin}/`,
    ...(trustRegistryUrl !== undefined ? { trustRegistryUrl } : {}),
    records: records.map(indexRecordFor),
  };
  out.set(INDEX_PATH, utf8(serialize(index)));
  return { files: out, index, registry };
}
