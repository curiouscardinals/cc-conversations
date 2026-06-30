import { NextRequest, NextResponse } from "next/server";

function unauthorized() {
  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="Protected Site", charset="UTF-8"' },
  });
}

export function middleware(req: NextRequest) {
  // Server-only secrets (must NOT be NEXT_PUBLIC_*, which would ship to the browser).
  const expectedUser = process.env.BASIC_AUTH_USER;
  const expectedPass = process.env.BASIC_AUTH_PASS;
  if (!expectedUser || !expectedPass) return unauthorized(); // fail closed

  const header = req.headers.get("authorization") ?? "";
  const sp = header.indexOf(" ");
  if (sp === -1) return unauthorized();
  const scheme = header.slice(0, sp);
  const encoded = header.slice(sp + 1).trim();
  if (scheme.toLowerCase() !== "basic" || !encoded) return unauthorized(); // RFC 7617: scheme is case-insensitive

  let decoded: string;
  try {
    // fatal:true rejects malformed UTF-8 outright instead of substituting U+FFFD
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0)),
    );
  } catch {
    return unauthorized(); // malformed base64 or UTF-8 -> 401, not 500
  }

  const sep = decoded.indexOf(":"); // split on FIRST colon (password may contain colons)
  if (sep === -1) return unauthorized();
  const user = decoded.slice(0, sep);
  const pass = decoded.slice(sep + 1);

  if (user === expectedUser && pass === expectedPass) return NextResponse.next();
  return unauthorized();
}

export const config = {
  // Gate everything except framework internals (_next/*) and the favicon.
  // /api is intentionally gated; same-origin fetches resend the header after auth.
  matcher: ["/((?!_next/|favicon\\.ico$).*)"],
};
