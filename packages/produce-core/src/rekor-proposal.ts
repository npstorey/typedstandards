// Rekor `hashedrekord` v0.0.1 proposal-body codec — pure external-proof
// request/response handling.
//
// Builds the JSON body a caller submits to a Rekor transparency log and
// parses the log's response into the fields worth persisting alongside the
// package. NO `fetch` anywhere in this package — submission stays
// implementation-side; verify-core's `rekor` / `rekor-inclusion` modules run
// the verification legs (hash parity + offline Merkle inclusion).
//
// Rekor's hashedrekord verifier applies Ed25519ph for bare Ed25519 keys,
// which pins the body's invariants:
//   - `data.hash.algorithm` must be `sha512`;
//   - `data.hash.value` must be hex(SHA-512(signed message)) — the Ed25519ph
//     prehash of the UTF-8 envelope-hash hex string, i.e. verify-core's
//     `rekorHashForPackage`;
//   - `signature.content` must be an Ed25519ph signature over the same
//     message (see `signEnvelopeHash`);
//   - `publicKey.content` must be base64(PEM-wrapped SPKI DER).

import { rekorHashForPackage } from '@typedstandards/verify-core';
import { derPublicKeyToPemBase64 } from './signing.ts';

/** The `hashedrekord` v0.0.1 proposal body (the submission JSON). */
export interface RekorProposalBody {
  apiVersion: '0.0.1';
  kind: 'hashedrekord';
  spec: {
    data: {
      hash: { algorithm: 'sha512'; value: string };
    };
    signature: {
      content: string;
      publicKey: { content: string };
    };
  };
}

/** The response fields worth persisting as the package's log proof. */
export interface RekorResult {
  entryId: string;
  logIndex: number;
  /** The entry's inclusion proof, JSON-stringified (`{}` when the log's
   *  response carried none). */
  inclusionProof: string;
  /** The entry's canonical leaf bytes (base64 `body`) — captured so a
   *  verifier can recompute the RFC 6962 leaf and verify Merkle inclusion
   *  OFFLINE. Null when the response carried none. */
  entryBody: string | null;
}

/**
 * Build the `hashedrekord` proposal body for a signed envelope. The
 * `signatureB64` / `publicKeyDerB64` values are the `signature` / `publicKey`
 * fields of a `SignResult`.
 */
export function buildRekorProposal(
  envelopeHashHex: string,
  signatureB64: string,
  publicKeyDerB64: string,
): RekorProposalBody {
  const sha512HashHex = rekorHashForPackage(envelopeHashHex);
  const pubKeyPemB64 = derPublicKeyToPemBase64(publicKeyDerB64);

  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: {
        hash: { algorithm: 'sha512', value: sha512HashHex },
      },
      signature: {
        content: signatureB64,
        publicKey: { content: pubKeyPemB64 },
      },
    },
  };
}

/**
 * Parse a Rekor log-entry creation response
 * (`{ [entryId]: { body, logIndex, verification: { inclusionProof }, … } }`)
 * into the persistable proof fields. Throws on a response that does not carry
 * a usable entry — the caller decides how a failed submission degrades.
 */
export function parseRekorResponse(json: unknown): RekorResult {
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    throw new Error('Rekor response must be an object keyed by entry id');
  }
  const entries = Object.entries(json as Record<string, unknown>);
  if (entries.length === 0) {
    throw new Error('Rekor response contains no entries');
  }
  const [entryId, entryValue] = entries[0];
  if (typeof entryValue !== 'object' || entryValue === null) {
    throw new Error('Rekor entry must be an object');
  }
  const entry = entryValue as {
    logIndex?: unknown;
    verification?: { inclusionProof?: unknown };
    body?: unknown;
  };
  if (typeof entry.logIndex !== 'number') {
    throw new Error('Rekor entry is missing a numeric logIndex');
  }

  return {
    entryId,
    logIndex: entry.logIndex,
    inclusionProof: JSON.stringify(entry.verification?.inclusionProof || {}),
    // The base64 `body` the log canonicalized — the RFC 6962 leaf input.
    entryBody: typeof entry.body === 'string' ? entry.body : null,
  };
}
