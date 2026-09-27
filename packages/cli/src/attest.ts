// `attest` (typedstandards#113 G0 D10 as corrected): an attestation/supersedes,
// revises, corroborates or contradicts node for a target record, signed on the same
// key path as `sign` and `withdraw`. `withdraws` stays `withdraw`'s; `reinstates`
// and `endorses` are not signed here.

import {
  buildAttestationNode,
  deriveKeyDerivedIdentifierFromKey,
  signEnvelopeHash,
  type AttestationInput,
} from '@typedstandards/produce-core';
import { ATTESTATION_AUTHORIZATION_RULES, checkAttestationNode, isKeyDerivedIdentifier } from '@typedstandards/verify-core';
import { CliError, EXIT, usageError } from './errors.ts';
import { checkAttestInput, readJson, type JsonObject } from './input.ts';
import type { Io } from './io.ts';
import { SITE_TABLES } from './readings.ts';
import { readSeed } from './seed.ts';
import { checkCarriedNode } from './verify.ts';

export const ATTEST_OPTIONS = {
  input: { type: 'string' },
} as const;

export interface AttestValues {
  input?: string;
}

export async function attestCommand(values: AttestValues, io: Io): Promise<JsonObject> {
  if (values.input === undefined) {
    throw usageError('--input is required: type, targetNodeId, signer and the type\'s payload as JSON, or - for standard input');
  }
  const input = checkAttestInput(readJson(io, values.input, '--input'));
  for (const key of ['packageId', 'createdAt', 'signingKeyId']) {
    if (input[key] === '') throw usageError(`${key} must not be empty; omit it to have it filled`);
  }

  const seed = readSeed(io.env);
  let printed: JsonObject;
  try {
    const identifier = deriveKeyDerivedIdentifierFromKey(seed);
    const signer = input['signer'] as JsonObject;
    const filled = {
      ...input,
      packageId: input['packageId'] ?? io.uuid(),
      createdAt: input['createdAt'] ?? io.now().toISOString(),
      signingKeyId: input['signingKeyId'] ?? identifier,
      signer: 'identifier' in signer ? signer : { ...signer, identifier },
    } as unknown as AttestationInput;
    const { node, nodeId } = buildAttestationNode(filled);
    const signature = signEnvelopeHash(nodeId, seed, filled.signingKeyId);
    printed = JSON.parse(JSON.stringify({ node, nodeId, signature })) as JsonObject;
  } finally {
    seed.fill(0);
  }

  // Before printing, verify-core's per-node check reads the node as a verifier
  // would. A publisher-only node (supersedes, revises) is checked against the
  // seed's own key as the target record's signing key and the node's identifier as
  // the target's signer, as `withdraw` does; an any-with-binding node
  // (corroborates, contradicts) with no registry. Integrity and the signature must
  // hold, and a did:key signer identifier binds only by derivation, so one the seed
  // does not derive fails here. Any other identifier prints: a verifier binds it
  // only through the target record's own signing key or a registry fetched from
  // its declared URL, so a reading other than `authorized` prints on stderr at its
  // tier (G0 D6 as corrected).
  const carried = checkCarriedNode(printed, 'the signed attestation');
  const identifier = (carried.node['signer'] as { identifier: string }).identifier;
  const publicKey = carried.signature?.publicKey ?? '';
  const publisherOnly = ATTESTATION_AUTHORIZATION_RULES[input.type] === 'publisher-only';
  const check = checkAttestationNode(carried, publisherOnly ? { target: { signerIdentifier: identifier, publicKey } } : {});
  const tier = SITE_TABLES.ATTESTATION_AUTHORIZATION_SIGNALS[check.status];
  const unboundDidKey = isKeyDerivedIdentifier(identifier) && !check.keyBound;
  if (!check.nodeIdMatches || check.signatureValid !== true || unboundDidKey || tier === 'alarm' || check.missingFields.length > 0) {
    throw new CliError(
      EXIT.verificationFailed,
      `the signed attestation did not verify offline, so nothing was printed: nodeId ${check.nodeIdMatches ? 'matches' : 'does not match'}, ` +
        `signature ${String(check.signatureValid)}, authorization ${check.status}` +
        (unboundDidKey ? `, and ${identifier} is not the seed's did:key` : '') +
        (check.missingFields.length > 0 ? `, missing ${check.missingFields.join(', ')}` : ''),
    );
  }
  if (check.status !== 'authorized') {
    io.stderr(
      `typedstandards attest: authorization: ${check.status} (${tier})` +
        (check.status === 'key_unbound'
          ? `: a verifier binds ${identifier} to this key only through a trust registry fetched from its declared URL\n`
          : '\n'),
    );
  }
  return printed;
}
