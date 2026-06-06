import { renderBadgeSvg } from "@/lib/badge-asset";

// Serve the embeddable verify badge (#116 WS3 Phase E, ADR-0013) as a static SVG.
// A host embeds it via a plain <img>, so it runs NO third-party JS on the host
// page — the safe, on-model embed. The badge is a calm CALL TO ACTION, never a
// verdict (see badge-asset.ts): the real verification result lives only at /verify.
//
// - CORS-open so any host (not just typedstandards.org) can <img> it cross-origin.
// - image/svg+xml + a long cache (the asset is stable; the wording never encodes a
//   per-package state, so it is safe to cache hard).
// - `?theme=dark` selects the dark palette.

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, OPTIONS",
} as const;

export function GET(request: Request) {
  const theme = new URL(request.url).searchParams.get("theme") === "dark" ? "dark" : "light";
  return new Response(renderBadgeSvg(theme), {
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "cache-control": "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400",
      ...CORS,
    },
  });
}

export function OPTIONS() {
  return new Response(null, {
    headers: { ...CORS, "access-control-max-age": "86400" },
  });
}
