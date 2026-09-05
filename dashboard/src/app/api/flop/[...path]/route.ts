import { NextRequest, NextResponse } from "next/server";

const API_URL = "http://127.0.0.1:8000";

async function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname.replace(/^\/api\/flop/, "");
  const url = `${API_URL}${path}${request.nextUrl.search}`;

  const apiKey = process.env.FLOP_API_KEY;

  if (!apiKey) {
    return NextResponse.json(
      { detail: "Dashboard API authentication is not configured" },
      { status: 500 }
    );
  }

  const headers = new Headers(request.headers);
  headers.set("X-API-Key", apiKey);
  headers.delete("host");

  const response = await fetch(url, {
    method: request.method,
    headers,
    body:
      request.method === "GET" || request.method === "HEAD"
        ? undefined
        : await request.arrayBuffer(),
    cache: "no-store",
  });

  const responseHeaders = new Headers(response.headers);
  responseHeaders.delete("content-encoding");
  responseHeaders.delete("content-length");

  return new NextResponse(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

export {
  proxy as GET,
  proxy as POST,
  proxy as PUT,
  proxy as PATCH,
  proxy as DELETE,
  proxy as HEAD,
};
