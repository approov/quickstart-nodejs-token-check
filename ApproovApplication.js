'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

loadEnvFile(path.join(__dirname, '.env'));

const SERVER_HOSTNAME = process.env.SERVER_HOSTNAME || 'localhost';
const HTTP_PORT = parsePort(process.env.HTTP_PORT, 8080);

const APPROOV_SECRET_BASE64URL =
  process.env.APPROOV_BASE64URL_SECRET || process.env.APPROOV_BASE64_SECRET;

if (!hasText(APPROOV_SECRET_BASE64URL)) {
  console.error('APPROOV_BASE64URL_SECRET environment variable is not set');
  process.exit(1);
}

const APPROOV_SECRET = base64UrlDecodeToBuffer(APPROOV_SECRET_BASE64URL.trim());

let approovEnabled = true;
let tokenBindingEnabled = true;

const HEADER_NAMES = Object.freeze({
  APPROOV_TOKEN: 'approov-token',
  AUTHORIZATION: 'authorization',
  CONTENT_DIGEST: 'content-digest',
});

const ROUTES = Object.freeze([
  { method: 'GET', path: '/', handler: homeHandler, requiresApproov: false },
  {
    method: 'GET',
    path: '/approov-state',
    handler: approovStateHandler,
    requiresApproov: false,
  },
  {
    method: 'POST',
    path: '/approov/enable',
    handler: enableApproovHandler,
    requiresApproov: false,
  },
  {
    method: 'POST',
    path: '/approov/disable',
    handler: disableApproovHandler,
    requiresApproov: false,
  },
  {
    method: 'POST',
    path: '/token-binding/enable',
    handler: enableTokenBindingHandler,
    requiresApproov: false,
  },
  {
    method: 'POST',
    path: '/token-binding/disable',
    handler: disableTokenBindingHandler,
    requiresApproov: false,
  },
  {
    method: 'GET',
    path: '/unprotected',
    handler: unprotectedHandler,
    requiresApproov: false,
  },
  {
    method: 'GET',
    path: '/token-check',
    handler: tokenCheckHandler,
    requiresApproov: true,
  },
  {
    method: 'GET',
    path: '/token-binding',
    handler: tokenBindingHandler,
    requiresApproov: true,
  },
  {
    method: 'GET',
    path: '/token-double-binding',
    handler: tokenDoubleBindingHandler,
    requiresApproov: true,
  },
]);

const ROUTE_TABLE = new Map(
  ROUTES.map((route) => [`${route.method} ${route.path}`, route])
);

const MIDDLEWARE = Object.freeze([approovTokenVerifier]);

const server = http.createServer((req, res) => {
  const requestInfo = parseRequest(req);
  const route = ROUTE_TABLE.get(`${requestInfo.method} ${requestInfo.path}`);

  if (!route) {
    writeJson(res, 404, { error: 'not_found' });
    return;
  }

  const ctx = {
    req,
    res,
    route,
    method: requestInfo.method,
    path: requestInfo.path,
    headers: req.headers,
    state: {},
  };

  try {
    runMiddleware(ctx, MIDDLEWARE, route.handler);
  } catch (error) {
    console.error('Unhandled error:', error);
    writeJson(res, 500, { error: 'server_error' });
  }
});

server.listen(HTTP_PORT, SERVER_HOSTNAME, () => {
  console.log(
    `Approov demo API running at http://${SERVER_HOSTNAME}:${HTTP_PORT}`
  );
});

function homeHandler(ctx) {
  writeJson(
    ctx.res,
    200,
    infoPayload(`Approov demo API is running on port ${HTTP_PORT}.`)
  );
}

function approovStateHandler(ctx) {
  writeJson(ctx.res, 200, statePayload());
}

function enableApproovHandler(ctx) {
  approovEnabled = true;
  tokenBindingEnabled = true;
  writeJson(ctx.res, 200, statePayload());
}

function disableApproovHandler(ctx) {
  approovEnabled = false;
  tokenBindingEnabled = false;
  writeJson(ctx.res, 200, statePayload());
}

function enableTokenBindingHandler(ctx) {
  tokenBindingEnabled = true;
  writeJson(ctx.res, 200, statePayload());
}

function disableTokenBindingHandler(ctx) {
  tokenBindingEnabled = false;
  writeJson(ctx.res, 200, statePayload());
}

function unprotectedHandler(ctx) {
  writeJson(
    ctx.res,
    200,
    infoPayload("Unprotected endpoint '/unprotected'; no Approov checks performed.")
  );
}

function tokenCheckHandler(ctx) {
  writeJson(
    ctx.res,
    200,
    infoPayload("Protected endpoint '/token-check'; Approov token verified.")
  );
}

function tokenBindingHandler(ctx) {
  const authorization = headerValue(ctx.headers, HEADER_NAMES.AUTHORIZATION);
  const response = infoPayload(
    "Protected endpoint '/token-binding'; Approov token binding enforced."
  );
  response.authorizationHeaderPresent = hasText(authorization);
  writeJson(ctx.res, 200, response);
}

function tokenDoubleBindingHandler(ctx) {
  const authorization = headerValue(ctx.headers, HEADER_NAMES.AUTHORIZATION);
  const contentDigest = headerValue(ctx.headers, HEADER_NAMES.CONTENT_DIGEST);
  const response = infoPayload(
    "Protected endpoint '/token-double-binding'; dual token binding enforced."
  );
  response.authorizationHeaderPresent = hasText(authorization);
  response.contentDigestHeaderPresent = hasText(contentDigest);
  writeJson(ctx.res, 200, response);
}

function approovTokenVerifier(ctx, next) {
  const route = ctx.route;
  if (!route || !route.requiresApproov) {
    next();
    return;
  }

  if (!approovEnabled) {
    next();
    return;
  }

  const token = readApproovToken(ctx.headers);
  if (!hasText(token)) {
    unauthorized(ctx.res, 'Missing Approov-Token header.');
    return;
  }

  let claims;
  try {
    claims = verifyApproovToken(token);
  } catch (error) {
    unauthorized(ctx.res, error.message);
    return;
  }

  if (tokenBindingEnabled && needsBindingCheck(route.path)) {
    const bindingValue = extractBindingValue(route.path, ctx.headers);
    if (!hasText(bindingValue) || !isBindingValid(bindingValue, claims)) {
      unauthorized(ctx.res, 'Invalid token binding.');
      return;
    }
  }

  ctx.state.approovClaims = claims;
  next();
}

function verifyApproovToken(token) {
  const parsed = parseJwt(token);

  if (parsed.header.alg !== 'HS256') {
    throw new Error(`Unsupported token alg: ${parsed.header.alg || 'unknown'}.`);
  }

  const expectedSignature = signHmac(parsed.signingInput, APPROOV_SECRET);
  if (!bufferEquals(expectedSignature, parsed.signature)) {
    throw new Error('Approov token signature verification failed.');
  }

  validateExpiration(parsed.payload);
  return parsed.payload;
}

function parseJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Approov token is not a valid JWT.');
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const headerJson = base64UrlDecodeToString(headerB64);
  const payloadJson = base64UrlDecodeToString(payloadB64);
  const signature = base64UrlDecodeToBuffer(signatureB64);

  return {
    header: parseJson(headerJson, 'header'),
    payload: parseJson(payloadJson, 'payload'),
    signature,
    signingInput: `${headerB64}.${payloadB64}`,
  };
}

function needsBindingCheck(pathname) {
  return pathname === '/token-binding' || pathname === '/token-double-binding';
}

function extractBindingValue(pathname, headers) {
  if (pathname === '/token-binding') {
    return trimOrNull(headerValue(headers, HEADER_NAMES.AUTHORIZATION));
  }

  const authorization = trimOrNull(
    headerValue(headers, HEADER_NAMES.AUTHORIZATION)
  );
  const digest = trimOrNull(
    headerValue(headers, HEADER_NAMES.CONTENT_DIGEST)
  );

  if (!hasText(authorization) || !hasText(digest)) {
    return null;
  }

  return authorization + digest;
}

function isBindingValid(bindingValue, claims) {
  const expected = typeof claims.pay === 'string' ? claims.pay.trim() : '';
  if (!hasText(expected)) {
    return false;
  }

  const computed = hashBase64(bindingValue);
  return safeStringEqual(expected, computed);
}

function validateExpiration(claims) {
  const exp = Number(claims.exp);
  if (!Number.isFinite(exp)) {
    throw new Error('Approov token missing exp claim.');
  }

  const now = Math.floor(Date.now() / 1000);
  if (exp <= now) {
    throw new Error('Approov token expired.');
  }
}

function statePayload() {
  return {
    approovEnabled,
    tokenBindingEnabled,
  };
}

function infoPayload(details) {
  return {
    ...statePayload(),
    details,
  };
}

function readApproovToken(headers) {
  return trimOrNull(headerValue(headers, HEADER_NAMES.APPROOV_TOKEN));
}

function headerValue(headers, name) {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function runMiddleware(ctx, middlewares, handler) {
  let index = -1;

  const dispatch = () => {
    index += 1;
    if (index < middlewares.length) {
      middlewares[index](ctx, dispatch);
      return;
    }
    handler(ctx);
  };

  dispatch();
}

function parseRequest(req) {
  const host = req.headers.host || `${SERVER_HOSTNAME}:${HTTP_PORT}`;
  const url = new URL(req.url || '/', `http://${host}`);
  return {
    path: url.pathname,
    method: (req.method || 'GET').toUpperCase(),
  };
}

function unauthorized(res, message) {
  writeJson(res, 401, { error: 'unauthorized', message });
}

function writeJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-cache',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function signHmac(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest();
}

function hashBase64(value) {
  return crypto
    .createHash('sha256')
    .update(value, 'utf8')
    .digest('base64');
}

function bufferEquals(left, right) {
  if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right)) {
    return false;
  }
  if (left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

function safeStringEqual(left, right) {
  if (!hasText(left) || !hasText(right)) {
    return false;
  }
  return bufferEquals(Buffer.from(left), Buffer.from(right));
}

function parseJson(value, label) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`Approov token ${label} is not valid JSON.`);
  }
}

function base64UrlDecodeToString(value) {
  return base64UrlDecodeToBuffer(value).toString('utf8');
}

function base64UrlDecodeToBuffer(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    '='
  );
  return Buffer.from(padded, 'base64');
}

function parsePort(value, fallback) {
  if (!hasText(value)) {
    return fallback;
  }
  const port = Number.parseInt(value, 10);
  return Number.isFinite(port) ? port : fallback;
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function trimOrNull(value) {
  return value == null ? null : value.trim();
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const content = fs.readFileSync(filePath, 'utf8');
  content.split(/\r?\n/).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      return;
    }
    const index = trimmed.indexOf('=');
    if (index <= 0) {
      return;
    }
    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  });
}
