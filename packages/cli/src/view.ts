// `view` (typedstandards#109 G0 D3): the commitment view a host serves, built by
// produce-core's `buildCommitmentView`, with the signed package inline. Every
// signed claim in the view is copied from the package; the flags supply only what
// a host decides (visibility, locations, a title). Under a self-certifying signer
// (a did:key at bindingTier "pseudonymous") trustRegistryUrl may be omitted, and
// produce-core then checks the identifier against the signature's key.
//
// `--attestation` carries any lifecycle node (`withdraws`, `reinstates`,
// `supersedes`, `revises`) into `lifecycleAttestations`; `--withdrawal` is its
// alias (typedstandards#113 G0 D10). This version carries no claim-to-claim node in
// a view (G0 D6), so `corroborates`, `contradicts` and `endorses` are refused.

import { buildCommitmentView, type CommitmentLifecycle, type SignerIdentity } from '@typedstandards/produce-core';
import { ATTESTATION_CONTRADICTS, ATTESTATION_CORROBORATES, verifyLifecycleChain } from '@typedstandards/verify-core';
import { CliError, EXIT, usageError } from './errors.ts';
import { isObject, readJson, type JsonObject } from './input.ts';
import type { Io } from './io.ts';
import { checkCarriedNode, checkSignedDocument, failureSummary, reportVerdict, verifyOffline } from './verify.ts';

export const VIEW_OPTIONS = {
  signed: { type: 'string' },
  attestation: { type: 'string', multiple: true },
  withdrawal: { type: 'string', multiple: true },
  visibility: { type: 'string' },
  'trust-registry-url': { type: 'string' },
  'package-url': { type: 'string' },
  title: { type: 'string' },
} as const;

export interface ViewValues {
  signed?: string;
  attestation?: string[];
  withdrawal?: string[];
  visibility?: string;
  'trust-registry-url'?: string;
  'package-url'?: string;
  title?: string;
}

const optionalString = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

// The claim-to-claim sub-types (spec §8.12.1), which a view does not carry.
const CLAIM_TO_CLAIM = [ATTESTATION_CORROBORATES, ATTESTATION_CONTRADICTS, 'attestation/endorses/v1'];

export async function viewCommand(values: ViewValues, io: Io): Promise<JsonObject> {
  if (values.signed === undefined) throw usageError('--signed is required: a file sign printed');
  if (values.visibility === undefined || values.visibility === '') {
    throw usageError('--visibility is required (for example public or sealed); a view states its disclosure state and it is never defaulted');
  }
  const signed = checkSignedDocument(readJson(io, values.signed, '--signed'), '--signed');
  const given = [
    ...(values.withdrawal ?? []).map((path) => ({ flag: '--withdrawal', path })),
    ...(values.attestation ?? []).map((path) => ({ flag: '--attestation', path })),
  ];
  const carried = given.map(({ flag, path }) => {
    const c = checkCarriedNode(readJson(io, path, flag), `${flag} ${path}`);
    const type = c.node['type'];
    if (typeof type === 'string' && CLAIM_TO_CLAIM.includes(type)) {
      throw usageError(`${flag} ${path} is an ${type}, a claim-to-claim node: this version carries none in a view (typedstandards#113 G0 D6)`);
    }
    if (c.node['targetNodeId'] !== signed.envelopeHash) {
      throw usageError(`a ${flag} targets ${String(c.node['targetNodeId'])}, not this record (${signed.envelopeHash})`);
    }
    return c;
  });

  // A host serves only a record that verifies, with lifecycle nodes that verify.
  const verdict = await verifyOffline(io, { package: signed.package, packageHash: signed.envelopeHash, signature: signed.signature, carried });
  if (!verdict.ok || verdict.checks.envelopeIntegrity.status !== 'verified' || verdict.checks.signatureValid !== true) {
    reportVerdict(io, 'view', verdict);
    throw new CliError(EXIT.verificationFailed, `the record does not verify offline, so no view was built: ${failureSummary(verdict)}`);
  }
  reportVerdict(io, 'view', verdict);

  const pkg = signed.package;
  const metadata = isObject(pkg['metadata']) ? pkg['metadata'] : {};
  const signer = isObject(pkg['signer']) ? pkg['signer'] : undefined;
  let lifecycle: CommitmentLifecycle | undefined;
  if (carried.length > 0) {
    const life = verifyLifecycleChain(carried, signed.envelopeHash, optionalString(signer?.['identifier']) ?? '', {
      targetPublicKey: signed.signature.publicKey,
    });
    lifecycle = {
      status: life.status,
      ...(life.withdrawnAt ? { withdrawnAt: life.withdrawnAt } : {}),
      ...(life.withdrawnReason ? { withdrawnReason: life.withdrawnReason } : {}),
      ...(life.reinstatedAt ? { reinstatedAt: life.reinstatedAt } : {}),
      ...(life.reinstatedReason ? { reinstatedReason: life.reinstatedReason } : {}),
      ...(life.supersededAt ? { supersededAt: life.supersededAt } : {}),
      ...(life.successorNodeId ? { successorNodeId: life.successorNodeId } : {}),
    };
  }

  let view: Record<string, unknown>;
  try {
    view = buildCommitmentView({
      packageHash: signed.envelopeHash,
      ...(values['package-url'] !== undefined ? { packageUrl: values['package-url'] } : {}),
      visibility: values.visibility,
      captureMethod: optionalString(metadata['captureMethod']) ?? null,
      contentProfile: optionalString(metadata['contentProfile']) ?? null,
      producerProfile: optionalString(pkg['producerProfile']),
      type: optionalString(pkg['type']),
      signer: signer as SignerIdentity | undefined,
      contentHash: isObject(pkg['contentHash']) ? (pkg['contentHash'] as Record<string, string>) : undefined,
      contentCanonicalization: optionalString(pkg['contentCanonicalization']),
      signature: { ...signed.signature },
      ...(lifecycle ? { lifecycle } : {}),
      lifecycleAttestations: carried,
      ...(values['trust-registry-url'] !== undefined ? { trustRegistryUrl: values['trust-registry-url'] } : {}),
      subjectTitle: values.title,
      subjectSummary: optionalString(pkg['summary']),
    });
  } catch (err) {
    throw usageError(`produce-core could not build the view: ${(err as Error).message}`);
  }
  return JSON.parse(JSON.stringify({ ...view, package: pkg })) as JsonObject;
}
