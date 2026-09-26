// The only fetcher the commands hand verify-core (typedstandards#109 G0 D3): it
// sends no request. It answers a URL it was given local bytes for, and refuses
// every other, counting the refusals so a caller can say what was not checked.

import type { FetchLike } from '@typedstandards/verify-core';

export interface OfflineFetch {
  fetch: FetchLike;
  /** The URLs a check asked for and was refused, in order. */
  refused: string[];
}

export function offlineFetch(local: ReadonlyMap<string, Uint8Array> = new Map()): OfflineFetch {
  const refused: string[] = [];
  const fetch: FetchLike = async (url) => {
    const bytes = local.get(url);
    if (bytes === undefined) {
      refused.push(url);
      throw new Error(`offline: no request is made for ${url}`);
    }
    const body = new Uint8Array(bytes).buffer;
    const text = async () => new TextDecoder().decode(bytes);
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      arrayBuffer: async () => body,
      text,
      json: async () => JSON.parse(await text()) as unknown,
    };
  };
  return { fetch, refused };
}
