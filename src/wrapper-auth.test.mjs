import assert from "node:assert/strict";
import test from "node:test";

import {
  AUTH_COOKIE,
  extractCredential,
  isAuthorized,
  issueCookieValue,
  parseCookies,
  safeEqual,
} from "./wrapper-auth.js";

const TOKEN = "tok_live_example_1234567890";
const SALT = "salt-example";

function req({ query = {}, headers = {} } = {}) {
  return { query, headers };
}

test("no credential at all is rejected", () => {
  assert.equal(isAuthorized(req(), TOKEN, SALT).ok, false);
  assert.equal(isAuthorized(req(), TOKEN, SALT).reason, "missing");
});

test("valid query token is accepted and asks for a cookie", () => {
  const out = isAuthorized(req({ query: { token: TOKEN } }), TOKEN, SALT);
  assert.equal(out.ok, true);
  assert.equal(out.source, "query");
  assert.equal(out.needsCookie, true);
});

test("wrong query token is rejected", () => {
  const out = isAuthorized(req({ query: { token: "nope" } }), TOKEN, SALT);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "invalid");
});

test("header and bearer credentials are accepted", () => {
  assert.equal(
    isAuthorized(req({ headers: { "x-openclaw-token": TOKEN } }), TOKEN, SALT).ok,
    true,
  );
  assert.equal(
    isAuthorized(req({ headers: { authorization: `Bearer ${TOKEN}` } }), TOKEN, SALT).ok,
    true,
  );
});

test("cookie round-trips and does not contain the token", () => {
  const cookie = issueCookieValue(TOKEN, SALT);
  assert.ok(!cookie.includes(TOKEN));
  const out = isAuthorized(
    req({ headers: { cookie: `theme=dark; ${AUTH_COOKIE}=${cookie}` } }),
    TOKEN,
    SALT,
  );
  assert.equal(out.ok, true);
  assert.equal(out.source, "cookie");
  assert.equal(out.needsCookie, false);
});

test("cookie from another salt (other boot) is rejected", () => {
  const cookie = issueCookieValue(TOKEN, "different-salt");
  const out = isAuthorized(
    req({ headers: { cookie: `${AUTH_COOKIE}=${cookie}` } }),
    TOKEN,
    SALT,
  );
  assert.equal(out.ok, false);
});

test("cookie validation is refused without a salt", () => {
  const cookie = issueCookieValue(TOKEN, SALT);
  const out = isAuthorized(req({ headers: { cookie: `${AUTH_COOKIE}=${cookie}` } }), TOKEN, undefined);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "missing");
});

test("the old auto-redirect style presence check no longer suffices", () => {
  // anything truthy that is not the token must fail (surrounding whitespace is trimmed)
  for (const value of ["1", "true", TOKEN.slice(0, -1), `${TOKEN}x`]) {
    assert.equal(isAuthorized(req({ query: { token: value } }), TOKEN, SALT).ok, false, value);
  }
  assert.equal(isAuthorized(req({ query: { token: ` ${TOKEN} ` } }), TOKEN, SALT).ok, true);
});

test("credential source precedence is query, header, bearer, cookie", () => {
  const cookie = issueCookieValue(TOKEN, SALT);
  const out = extractCredential(
    req({
      query: { token: "q" },
      headers: { "x-openclaw-token": "h", authorization: "Bearer b", cookie: `${AUTH_COOKIE}=${cookie}` },
    }),
  );
  assert.deepEqual(out, { value: "q", source: "query" });
});

test("parseCookies handles quoted and encoded values", () => {
  const parsed = parseCookies('a="x y"; b=c%20d; malformed');
  assert.equal(parsed.a, "x y");
  assert.equal(parsed.b, "c d");
  assert.equal(parsed.malformed, undefined);
});

test("safeEqual compares without throwing on length mismatch", () => {
  assert.equal(safeEqual("abc", "abc"), true);
  assert.equal(safeEqual("abc", "abcd"), false);
  assert.equal(safeEqual(undefined, ""), true);
});
