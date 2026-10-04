import { NextRequest, NextResponse } from "next/server";

import { API_URL } from "@/lib/api-target";
import { evaluateProxyRequest } from "@/lib/proxy-policy";

const PREFIX = "/api/flop";

function rejected(status: 404 | 405) {
  return NextResponse.json(
    { detail: status === 405 ? "Method not allowed" : "Not found" },
    { status, headers: status === 405 ? { Allow: "GET" } : undefined },
  );
}

export async function GET(request: NextRequest) {
  // Raw, still percent-encoded path, so encoded "." or "/" cannot slip through.
  const rest = request.nextUrl.pathname.slice(PREFIX.length);
  const segments = rest.startsWith("/") ? rest.slice(1).split("/") : [rest];

  const decision = evaluateProxyRequest(
    request.method,
    segments,
    request.nextUrl.searchParams,
  );

  if (!decision.allowed) {
    return rejected(decision.status);
  }

  const apiKey = process.env.FLOP_API_KEY;

  if (!apiKey) {
    return NextResponse.json(
      { detail: "Dashboard API authentication is not configured" },
      { status: 500 },
    );
  }

  // Forward only what the API needs; browser headers and cookies stay here.
  let response: Response;
  try {
    response = await fetch(`${API_URL}${decision.path}${decision.search}`, {
      method: "GET",
      headers: {
        Accept: request.headers.get("accept") ?? "application/json",
        "X-API-Key": apiKey,
      },
      cache: "no-store",
    });
  } catch {
    // Connection refused, DNS, reset: the API could not be reached. A fixed
    // message, so no internal error detail reaches the browser. Status codes
    // the API itself returns are passed through unchanged below.
    return NextResponse.json({ detail: "FLOP API unreachable" }, { status: 502 });
  }

  const responseHeaders = new Headers(response.headers);
  responseHeaders.delete("content-encoding");
  responseHeaders.delete("content-length");

  return new NextResponse(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

// Every other method is answered here and never reaches the API.
function methodNotAllowed() {
  return rejected(405);
}

export {
  methodNotAllowed as POST,
  methodNotAllowed as PUT,
  methodNotAllowed as PATCH,
  methodNotAllowed as DELETE,
  methodNotAllowed as HEAD,
};
