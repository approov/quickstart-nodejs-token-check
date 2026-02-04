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
const APPROOV_SECRET = resolveApproovSecret(APPROOV_SECRET_BASE64URL);

let approovEnabled = true;
let tokenBindingEnabled = true;

const HEADER_NAMES = Object.freeze({
  APPROOV_TOKEN: 'Approov-Token',
  AUTHORIZATION: 'Authorization',
  SESSION_ID: 'SessionId',
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
    bindingHeaders: [HEADER_NAMES.AUTHORIZATION],
  },
  {
    method: 'GET',
    path: '/token-double-binding',
    handler: tokenDoubleBindingHandler,
    requiresApproov: true,
    bindingHeaders: [HEADER_NAMES.AUTHORIZATION, HEADER_NAMES.SESSION_ID,],
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
  initializeRequestState(ctx);

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
  syncRequestState(ctx);
  writeJson(ctx.res, 200, statePayload());
}

function disableApproovHandler(ctx) {
  approovEnabled = false;
  tokenBindingEnabled = false;
  syncRequestState(ctx);
  writeJson(ctx.res, 200, statePayload());
}

function enableTokenBindingHandler(ctx) {
  tokenBindingEnabled = true;
  syncRequestState(ctx);
  writeJson(ctx.res, 200, statePayload());
}

function disableTokenBindingHandler(ctx) {
  tokenBindingEnabled = false;
  syncRequestState(ctx);
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
  const sessionId = headerValue(ctx.headers, HEADER_NAMES.SESSION_ID);
  const response = infoPayload(
    "Protected endpoint '/token-double-binding'; dual token binding enforced."
  );
  response.authorizationHeaderPresent = hasText(authorization);
  response.sessionIdHeaderPresent = hasText(sessionId);
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
    unauthorized(ctx, 'missing_approov_token', 'Missing Approov-Token header.');
    return;
  }

  let claims;
  try {
    claims = verifyApproovToken(token);
  } catch (error) {
    unauthorized(ctx, 'token_verification_failed', error.message);
    return;
  }

  const bindingHeaders = normalizeBindingHeaders(route.bindingHeaders);
  if (tokenBindingEnabled && bindingHeaders.length > 0) {
    const bindingValue = extractBindingValue(ctx.headers, bindingHeaders);
    if (!hasText(bindingValue)) {
      unauthorized(ctx, 'missing_binding_header', 'Missing binding header.');
      return;
    }
    if (!isBindingValid(bindingValue, claims)) {
      unauthorized(ctx, 'binding_mismatch', 'Invalid token binding.');
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

function normalizeBindingHeaders(bindingHeaders) {
  if (!Array.isArray(bindingHeaders)) {
    return [];
  }
  return bindingHeaders
    .map((header) => (typeof header === 'string' ? header.trim() : ''))
    .filter((header) => hasText(header));
}

function extractBindingValue(headers, bindingHeaders) {
  const values = [];
  for (const header of bindingHeaders) {
    const value = trimOrNull(headerValue(headers, header));
    if (!hasText(value)) {
      return null;
    }
    values.push(value);
  }
  return values.join('');
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

function initializeRequestState(ctx) {
  syncRequestState(ctx);
  ctx.state.logSummary = defaultSummaryForRoute(ctx.route, ctx.state);
  ctx.res.on('finish', () => {
    const status = ctx.res.statusCode;
    if (status === 200 || status === 401) {
      logRequestCompleted(ctx);
    }
  });
}

function syncRequestState(ctx) {
  ctx.state.approovEnabled = approovEnabled;
  ctx.state.tokenBindingEnabled = tokenBindingEnabled;
}

function defaultSummaryForRoute(route, state) {
  if (!route || !route.requiresApproov) {
    return 'ok';
  }
  if (!state.approovEnabled) {
    return 'approov_disabled';
  }
  return 'approov_ok';
}

function logRequestCompleted(ctx) {
  const state = ctx.state;
  const summary = ctx.state.logSummary || defaultSummaryForRoute(ctx.route, state);
  const socket = ctx.req.socket;
  const fields = {
    summary,
    method: ctx.method,
    path: ctx.path,
    status: ctx.res.statusCode,
    ip: normalizeIp(socket?.remoteAddress),
    port: socket?.localPort ?? HTTP_PORT,
    approovEnabled: state.approovEnabled,
    tokenBindingEnabled: state.tokenBindingEnabled,
    required_headers: requiredHeadersForRoute(ctx.route, state),
  };
  logInfo('http.request.completed', fields);
}

function requiredHeadersForRoute(route, state) {
  if (!route || !route.requiresApproov || !state.approovEnabled) {
    return [];
  }
  const required = [HEADER_NAMES.APPROOV_TOKEN];
  if (state.tokenBindingEnabled) {
    const bindingHeaders = normalizeBindingHeaders(route.bindingHeaders);
    for (const header of bindingHeaders) {
      if (!required.includes(header)) {
        required.push(header);
      }
    }
  }
  return required;
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
  if (!headers || typeof name !== 'string') {
    return undefined;
  }
  const value = headers[name.toLowerCase()];
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

function unauthorized(ctx, reason, message) {
  ctx.state.logSummary = `approov_failed:${reason}`;
  writeJson(ctx.res, 401, { error: 'unauthorized', message });
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

function logInfo(event, fields) {
  const line = formatLogLine(event, fields);
  console.log(line);
}

function logError(event, fields) {
  const line = formatLogLine(event, fields);
  console.error(line);
}

function formatLogLine(event, fields) {
  const timestamp = formatTimestamp(new Date());
  const formattedFields = formatLogFields(fields);
  return `[${timestamp}] ${event} ${formattedFields}`;
}

function formatLogFields(fields) {
  return Object.entries(fields)
    .map(([key, value]) => `"${key}":${formatLogValue(value)}`)
    .join(',');
}

function formatLogValue(value) {
  if (value === undefined) {
    return 'null';
  }
  return JSON.stringify(value);
}

function formatTimestamp(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

function normalizeIp(value) {
  if (!hasText(value)) {
    return 'unknown';
  }
  if (value === '::1') {
    return '127.0.0.1';
  }
  if (value.startsWith('::ffff:')) {
    return value.slice(7);
  }
  return value;
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

function resolveApproovSecret(value) {
  const placeholder = 'approov_base64url_secret_here';
  if (!hasText(value) || value.trim() === placeholder) {
    logError('approov.config', { summary: 'Required secret is not set' });
    process.exit(1);
  }

  try {
    return decodeBase64Secret(value.trim());
  } catch (error) {
    logError('approov.config', {
      summary: 'Required secret is invalid',
      error: error instanceof Error ? error.message : String(error),
    });
    process.exit(1);
  }
}

function decodeBase64Secret(value) {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) {
    throw new Error('Secret contains invalid characters.');
  }

  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    '='
  );
  const buffer = Buffer.from(padded, 'base64');
  if (buffer.length === 0) {
    throw new Error('Secret is empty after decoding.');
  }

  const reencoded = buffer.toString('base64').replace(/=+$/g, '');
  const normalizedNoPad = normalized.replace(/=+$/g, '');
  if (reencoded !== normalizedNoPad) {
    throw new Error('Secret is not valid base64.');
  }

  return buffer;
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
