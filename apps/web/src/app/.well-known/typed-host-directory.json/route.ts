import { HOST_DIRECTORY } from "@/lib/host-directory";

// Serve the canonical Typed Standards host directory (#116 WS3 Phase D, Q47) at
// the stable well-known path `HOST_DIRECTORY_PATH`. The bytes come straight from
// the single `HOST_DIRECTORY` constant, so the served document and the verifier's
// in-code source of truth cannot drift.
//
// - CORS-open (`Access-Control-Allow-Origin: *`) so forks of the verifier and the
//   embeddable badge (Phase E) — not just the same-origin typedstandards.org
//   verifier — can read it.
// - Statically rendered + cacheable, so it is trivially snapshot-able for an
//   offline bundle (download the JSON) and cheap to serve as a runtime dependency
//   of every verdict. Editorial roster changes ship on the next deploy.

export const dynamic = "force-static";

const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, OPTIONS",
} as const;

export function GET() {
  return new Response(JSON.stringify(HOST_DIRECTORY, null, 2) + "\n", {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=300, s-maxage=300, stale-while-revalidate=86400",
      ...CORS_HEADERS,
    },
  });
}

export function OPTIONS() {
  return new Response(null, {
    headers: { ...CORS_HEADERS, "access-control-max-age": "86400" },
  });
}
