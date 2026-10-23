// Wrapper-side authentication for the gateway proxy.
// The stock Railway wrapper 302s /openclaw to /openclaw?token=<live token> and
// injects `Authorization: Bearer <token>` on every proxied HTTP/WS request. With
// a public domain attached that hands full Control-UI + API access to anyone who
// asks. These helpers gate the proxy on a credential the caller must already
// hold. Nothing is handed out.
import crypto from "node:crypto";

export const AUTH_COOKIE = "oc_wrap_auth";
export const AUTH_COOKIE_MAX_AGE_MS = 12 * 60 * 60 * 1000;

function sha256(value) {
  return crypto.createHash("sha256").update(String(value ?? ""), "utf8").digest();
}

export function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(a), sha256(b));
}

// Session cookie value: HMAC over the live token with a per-boot salt, so the
// token itself never appears in the cookie and the cookie dies with the process.
export function issueCookieValue(token, salt) {
  return crypto
    .createHmac("sha256", String(salt ?? ""))
    .update(`openclaw-wrapper:${String(token ?? "")}`)
    .digest("base64url");
}
export function parseCookies(header) {
  const out = Object.create(null);
  if (typeof header !== "string" || header.length === 0) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (!name) continue;
    let value = part.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    out[name] = decodeURIComponent(value);
  }
  return out;
}
function bearerFromHeader(header) {
  if (typeof header !== "string") return undefined;
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : undefined;
}

// Credential presented by the caller, plus where it came from.
export function extractCredential(req) {
  const query = req?.query?.token;
  if (typeof query === "string" && query.trim()) {
    return { value: query.trim(), source: "query" };
  }
  const headerToken = req?.headers?.["x-openclaw-token"];
  if (typeof headerToken === "string" && headerToken.trim()) {
    return { value: headerToken.trim(), source: "header" };
  }
  const bearer = bearerFromHeader(req?.headers?.authorization);
  if (bearer) return { value: bearer, source: "bearer" };
  const cookie = parseCookies(req?.headers?.cookie)[AUTH_COOKIE];
  if (typeof cookie === "string" && cookie.length > 0) {
    return { value: cookie, source: "cookie" };
  }
  return null;
}

// `salt` is required so cookie credentials can be validated; omit it and cookie
// credentials are rejected.
export function isAuthorized(req, token, salt) {
  const cred = extractCredential(req);
  if (!cred) return { ok: false, reason: "missing" };
  if (!token) return { ok: false, reason: "unconfigured" };
  if (cred.source === "cookie") {
    if (!salt) return { ok: false, reason: "missing" };
    if (safeEqual(cred.value, issueCookieValue(token, salt))) {
      return { ok: true, source: cred.source, needsCookie: false };
    }
    return { ok: false, reason: "invalid" };
  }
  if (safeEqual(cred.value, token)) {
    return { ok: true, source: cred.source, needsCookie: cred.source === "query" };
  }
  return { ok: false, reason: "invalid" };
}

export function denyPage() {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>OpenClaw — authentication required</title>
<style>body{font:15px/1.5 ui-sans-serif,system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#0b0d10;color:#e6e8eb}
main{max-width:34rem;padding:2rem}code{background:#171b21;padding:.15rem .4rem;border-radius:.35rem}
h1{font-size:1.1rem}</style></head>
<body><main><h1>Authentication required</h1>
<p>This endpoint needs the gateway token. Open <code>/openclaw?token=YOUR_TOKEN</code> once;
the wrapper then keeps you signed in for this browser session.</p>
</main></body></html>`;
}