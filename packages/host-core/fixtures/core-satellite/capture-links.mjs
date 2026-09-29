// Capture links.golden.json from the site's own builders, apps/web/src/lib/badge-asset.ts
// at 41c43c9, over expected/records.json. From the repository root:
//   git show 41c43c9:apps/web/src/lib/badge-asset.ts > <tmp>/badge-asset.ts
//   node --experimental-strip-types packages/host-core/fixtures/core-satellite/capture-links.mjs \
//     <tmp>/badge-asset.ts packages/host-core/fixtures/core-satellite/expected/records.json \
//     packages/host-core/fixtures/core-satellite/links.golden.json
// A record's url is the index's host plus its bundle path (host-core's mapping, not
// the site's); everything else is the site's functions' output.
import fs from 'node:fs';
const [badge, indexPath, out] = process.argv.slice(2);
const { CANONICAL_ORIGIN, buildVerifyHref, buildEmbedHtml, buildEmbedMarkdown } = await import(badge);
const idx = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
const records = idx.records.map((r) => {
  const url = /^https?:\/\//i.test(r.bundle) ? r.bundle : `${idx.host}${r.bundle}`;
  return {
    name: r.name,
    url,
    verify: buildVerifyHref(CANONICAL_ORIGIN, url),
    html: buildEmbedHtml(CANONICAL_ORIGIN, url),
    markdown: buildEmbedMarkdown(CANONICAL_ORIGIN, url),
  };
});
fs.writeFileSync(out, `${JSON.stringify({ records }, null, 2)}\n`);
