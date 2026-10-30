// Check #15 resolves a vocabulary only for a profile type that is one of the
// table's own rows (spec §8.6); any other profile type reads
// `producerProfile_bundle_unresolved`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PROFILE_CAPTURE_VOCAB, captureVocabForProfile, checkCaptureMethodVocab } from './index.ts';

test('check 15 resolves only the table\'s own profile types', () => {
  for (const name of Object.getOwnPropertyNames(Object.prototype)) {
    const producerProfile = `${name}/x`;
    assert.equal(captureVocabForProfile(producerProfile, undefined), undefined, producerProfile);
    let result: ReturnType<typeof checkCaptureMethodVocab> | undefined;
    assert.doesNotThrow(() => {
      result = checkCaptureMethodVocab({ metadata: { captureMethod: 'chat-flow-stream' }, producerProfile });
    }, producerProfile);
    assert.deepEqual(
      result,
      { status: 'producerProfile_bundle_unresolved', captureMethod: 'chat-flow-stream', profileType: name },
      producerProfile,
    );
  }
});

test('check 15: the two rows still resolve their vocabularies', () => {
  for (const [profileType, method] of [
    ['ai-assisted-analysis', 'chat-flow-stream'],
    ['scripted-recomputation', 'script-run'],
  ] as const) {
    const producerProfile = `${profileType}/x`;
    assert.equal(captureVocabForProfile(producerProfile, undefined), PROFILE_CAPTURE_VOCAB[profileType]);
    assert.deepEqual(checkCaptureMethodVocab({ metadata: { captureMethod: method }, producerProfile }), {
      status: 'ok',
      captureMethod: method,
      profileType,
    });
  }
});
