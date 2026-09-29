// Capture the host-core oracle fixture from the example's served docs/ at b40c30f.
// Usage, from the repository root:
//   git -C <example checkout> archive b40c30f docs | tar -x -C <tmp>
//   node packages/host-core/fixtures/core-satellite/capture.mjs <tmp>/docs packages/host-core/fixtures/core-satellite
// Nothing here runs host-core: every expected output is a byte copy or a mechanical reshaping
// of records.json, so the fixture is an independent oracle.
import fs from 'node:fs';
import path from 'node:path';

const [docs, out] = process.argv.slice(2);
const json = (v) => `${JSON.stringify(v, null, 2)}\n`;
const read = (p) => JSON.parse(fs.readFileSync(path.join(docs, p), 'utf8'));
const write = (p, text) => {
  fs.mkdirSync(path.dirname(path.join(out, p)), { recursive: true });
  fs.writeFileSync(path.join(out, p), text);
};
const copy = (from, to) => {
  fs.mkdirSync(path.dirname(path.join(out, to)), { recursive: true });
  fs.copyFileSync(path.join(docs, from), path.join(out, to));
};

const rj = read('records.json');
const reg = read('.well-known/typed-publisher.json');
const origin = rj.host.replace(/\/$/, '');

const records = [];
for (const r of rj.records) {
  const b = read(r.bundle);
  // sign's shape: {package, envelopeHash, signature}; envelopeHash is the bundle's packageHash.
  write(`input/signed/${r.name}.signed.json`, json({ package: b.package, envelopeHash: b.packageHash, signature: b.signature }));
  const attestations = (b.lifecycleAttestations ?? []).map((c, i, all) => {
    const file = `withdrawals/${r.name}${all.length > 1 ? `-${i + 1}` : ''}.withdrawal.json`;
    // withdraw's shape: {node, nodeId, signature}, the carried node verbatim.
    write(`input/${file}`, json({ node: c.node, nodeId: c.nodeId, signature: c.signature }));
    return file;
  });
  records.push({
    name: r.name,
    signed: `signed/${r.name}.signed.json`,
    attestations,
    title: b.subjectTitle,
    extensions: { file: r.file, role: r.role, edgeId: r.edgeId, step: r.step },
  });
  copy(r.bundle, `expected/${r.bundle}`);
}
write('input/host.json', json({
  origin,
  visibility: 'public',
  registry: { $comment: reg.$comment },
  index: { $comment: rj.$comment },
  records,
}));
copy('.well-known/typed-publisher.json', 'expected/.well-known/typed-publisher.json');
copy('records.json', 'example-records.json');
write('expected/records.json', json({
  version: 1,
  $comment: rj.$comment,
  host: rj.host,
  trustRegistryUrl: rj.trustRegistryUrl,
  records: rj.records.map((r) => ({
    name: r.name,
    bundle: r.bundle,
    packageHash: r.packageHash,
    createdAt: r.createdAt,
    type: r.type,
    signer: r.signer,
    status: r.status,
    ...(r.withdrawn ? { withdrawn: r.withdrawn } : {}),
    extensions: { file: r.file, role: r.role, edgeId: r.edgeId, step: r.step },
  })),
}));
console.log(`records ${records.length}, attestations ${records.reduce((n, r) => n + r.attestations.length, 0)}`);
