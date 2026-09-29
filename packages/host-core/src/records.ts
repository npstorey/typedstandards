// The documents a host is handed, read back, and the lifecycle reading both the
// build and `verify` take of them (typedstandards#125 G0 D1, D6).
//
// The shape checks restate the CLI's `checkSignedDocument` and `checkCarriedNode`
// (packages/cli/src/verify.ts at 41c43c9), whose package exports no module: `sign`
// prints `{package, envelopeHash, signature}`, and `withdraw` and `attest` print
// `{node, nodeId, signature}`.

import {
  ATTESTATION_CONTRADICTS,
  ATTESTATION_CORROBORATES,
  verifyLifecycleChain,
  type CarriedLifecycleNode,
  type LifecycleResolution,
  type VerifySignatureEnvelope,
} from '@typedstandards/verify-core';
import { HostError, isObject, type JsonObject } from './json.ts';
import type { IndexRecord } from './served.ts';

export interface SignedDocument {
  package: JsonObject;
  envelopeHash: string;
  signature: VerifySignatureEnvelope;
}

export interface CarriedNode extends CarriedLifecycleNode {
  signature: VerifySignatureEnvelope;
}

const HEX_64 = /^[0-9a-f]{64}$/;

// The claim-to-claim sub-types (spec §8.12.1), which a view does not carry: the
// CLI's `view` refuses them too (typedstandards#113 G0 D6).
const CLAIM_TO_CLAIM = [ATTESTATION_CORROBORATES, ATTESTATION_CONTRADICTS, 'attestation/endorses/v1'];

function exactKeys(value: JsonObject, keys: readonly string[], what: string): void {
  const extra = Object.keys(value).filter((k) => !keys.includes(k));
  if (extra.length) throw new HostError(`${extra.join(', ')}: not part of ${what}`);
  const missing = keys.filter((k) => !(k in value));
  if (missing.length) throw new HostError(`${what} is missing ${missing.join(', ')}`);
}

export function checkSignature(value: unknown, where: string): VerifySignatureEnvelope {
  if (!isObject(value) || typeof value['signature'] !== 'string' || typeof value['publicKey'] !== 'string') {
    throw new HostError(`${where} must be an object with a signature and a publicKey string`);
  }
  for (const key of ['algorithm', 'kid']) {
    if (key in value && typeof value[key] !== 'string') throw new HostError(`${where}.${key} must be a string`);
  }
  return value as unknown as VerifySignatureEnvelope;
}

/** What `sign` prints: `{package, envelopeHash, signature}`. */
export function checkSignedDocument(value: unknown, where: string): SignedDocument {
  if (!isObject(value)) throw new HostError(`${where} must be what sign prints: {package, envelopeHash, signature}`);
  exactKeys(value, ['package', 'envelopeHash', 'signature'], `${where}, which sign prints`);
  if (!isObject(value['package'])) throw new HostError(`${where}: package must be an object`);
  if (typeof value['envelopeHash'] !== 'string' || !HEX_64.test(value['envelopeHash'])) {
    throw new HostError(`${where}: envelopeHash must be 64 lowercase hex characters`);
  }
  return {
    package: value['package'],
    envelopeHash: value['envelopeHash'],
    signature: checkSignature(value['signature'], `${where}: signature`),
  };
}

/** What `withdraw` and `attest` print: `{node, nodeId, signature}`. */
export function checkCarriedNode(value: unknown, where: string): CarriedNode {
  if (!isObject(value)) throw new HostError(`${where} must be what withdraw or attest prints: {node, nodeId, signature}`);
  exactKeys(value, ['node', 'nodeId', 'signature'], `${where}, which withdraw and attest print`);
  if (!isObject(value['node'])) throw new HostError(`${where}: node must be an object`);
  if (typeof value['nodeId'] !== 'string') throw new HostError(`${where}: nodeId must be a string`);
  checkSignature(value['signature'], `${where}: signature`);
  const type = value['node']['type'];
  if (typeof type === 'string' && CLAIM_TO_CLAIM.includes(type)) {
    throw new HostError(`${where} is an ${type}, a claim-to-claim node: a bundle carries lifecycle attestations only (typedstandards#113 G0 D6)`);
  }
  return value as unknown as CarriedNode;
}

export const signerOf = (pkg: JsonObject): JsonObject | undefined => (isObject(pkg['signer']) ? pkg['signer'] : undefined);

export const signerIdentifierOf = (pkg: JsonObject): string => {
  const id = signerOf(pkg)?.['identifier'];
  return typeof id === 'string' ? id : '';
};

/**
 * A record's lifecycle, read from the attestations its bundle carries, as the CLI's
 * `view` and `verify` read it: a node moves the status only when its key is bound
 * to the signer it names, and the record's own signing key is what binds it.
 */
export function lifecycleOf(carried: readonly CarriedLifecycleNode[], packageHash: string, pkg: JsonObject, signature: VerifySignatureEnvelope): LifecycleResolution {
  return verifyLifecycleChain([...carried], packageHash, signerIdentifierOf(pkg), { targetPublicKey: signature.publicKey });
}

/** The index's lifecycle fields for a resolution: `status`, then `withdrawn` or `superseded`. */
export function indexLifecycleOf(life: LifecycleResolution): Pick<IndexRecord, 'status' | 'withdrawn' | 'superseded'> {
  return {
    status: life.status,
    ...(life.status === 'withdrawn' ? { withdrawn: { at: life.withdrawnAt ?? '', ...(life.withdrawnReason !== undefined ? { reason: life.withdrawnReason } : {}) } } : {}),
    ...(life.status === 'superseded' ? { superseded: { at: life.supersededAt ?? '', successorNodeId: life.successorNodeId ?? '' } } : {}),
  };
}
