'use strict';
/**
 * Lambda@Edge viewer-request function.
 *
 * Deployed to CloudFront as a viewer-request trigger. Intercepts every
 * request before it reaches S3 and enforces the shared-password gate.
 *
 * Environment variables (set on the Lambda function, NOT here):
 *   PASSWORD_HASH  — SHA-256 hex digest of the plaintext password
 *   COOKIE_SECRET  — random 32-byte hex string used to HMAC-sign the auth cookie
 *
 * Flow:
 *   1. POST /login  → validate password, set signed HttpOnly cookie, redirect to /
 *   2. Any request with valid auth cookie → pass through to S3
 *   3. Anything else → redirect to /login
 */

const crypto = require('crypto');

// Cookie name stored in the browser
const AUTH_COOKIE = 'wsite_auth';
// Cookie lifetime: 7 days (guests may revisit)
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7;

// ─── helpers ───────────────────────────────────────────────────────────────

function sha256hex(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function hmacSign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex');
}

function makeCookieValue(secret) {
  const token = crypto.randomBytes(16).toString('hex');
  const sig = hmacSign(token, secret);
  return `${token}.${sig}`;
}

function verifyCookieValue(raw, secret) {
  if (!raw) return false;
  const [token, sig] = raw.split('.');
  if (!token || !sig) return false;
  const expected = hmacSign(token, secret);
  return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach((pair) => {
    const [k, ...rest] = pair.trim().split('=');
    cookies[k.trim()] = rest.join('=').trim();
  });
  return cookies;
}

function parseBody(request) {
  if (!request.body || !request.body.data) return {};
  let raw;
  if (request.body.encoding === 'base64') {
    raw = Buffer.from(request.body.data, 'base64').toString('utf-8');
  } else {
    raw = request.body.data;
  }
  const params = {};
  raw.split('&').forEach((pair) => {
    const [k, v] = pair.split('=').map(decodeURIComponent);
    params[k] = v;
  });
  return params;
}

function redirect(location, headers = {}) {
  return {
    status: '302',
    statusDescription: 'Found',
    headers: {
      location: [{ key: 'Location', value: location }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
      ...headers,
    },
  };
}

// ─── handler ───────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;
  const uri = request.uri;
  const method = request.method;

    // Values injected at CDK deploy time (Lambda@Edge does not support env vars)
  const passwordHash = '5fdf250a1a18b3f5aee82c9a79c6e631c252f644b23cb27f06ab2846e0395fe0';
  const cookieSecret = 'c3c73e5a9d2e02623d3a74b8d8f8e93c279c1580a9749fbaf2f9ed8856351890';

  // ── POST /login — validate submitted password ──
  if (method === 'POST' && (uri === '/login' || uri === '/login/')) {
    const body = parseBody(request);
    const submitted = (body['password'] || '').trim();
    const submittedHash = sha256hex(submitted);

    if (submittedHash !== passwordHash) {
      // Wrong password — redirect back to login with error flag
      return redirect('/login?error=1');
    }

    // Correct — issue signed cookie and send to home page
    const cookieVal = makeCookieValue(cookieSecret);
    const setCookie = `${AUTH_COOKIE}=${cookieVal}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`;

    return redirect('/', {
      'set-cookie': [{ key: 'Set-Cookie', value: setCookie }],
    });
  }

  // ── GET /login — always allowed through ──
  if (uri === '/login' || uri === '/login/' || uri === '/login/index.html') {
    return request;
  }

  // ── All other requests — check cookie ──
  const cookieHeader = (request.headers['cookie'] || []).map((c) => c.value).join('; ');
  const cookies = parseCookies(cookieHeader);
  const authCookie = cookies[AUTH_COOKIE];

  if (!verifyCookieValue(authCookie, cookieSecret)) {
    return redirect('/login');
  }

  return request;
};
