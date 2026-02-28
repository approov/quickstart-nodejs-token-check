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
  const ctx = {
    req,
    res,
    route: null,
    method: (req.method || 'GET').toUpperCase(),
    path: '/',
    headers: req.headers,
    state: {},
  };
  initializeRequestState(ctx);

  let requestInfo;
  try {
    requestInfo = parseRequest(req);
  } catch (error) {
    handleRequestError(ctx, error);
    return;
  }

  ctx.method = requestInfo.method;
  ctx.path = requestInfo.path;
  ctx.route = ROUTE_TABLE.get(`${ctx.method} ${ctx.path}`);
  ctx.state.logSummary = defaultSummaryForRoute(ctx.route, ctx.state);

  if (!ctx.route) {
    handleRequestError(
      ctx,
      createHttpError(404, 'not_found', 'Requested endpoint was not found.', {
        logSummary: 'not_found',
      })
    );
    return;
  }

  runMiddleware(ctx, MIDDLEWARE, ctx.route.handler, (error) => {
    if (error) {
      handleRequestError(ctx, error);
    }
  });
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
    next(
      createUnauthorizedError(
        'missing_approov_token',
        'Missing Approov-Token header.'
      )
    );
    return;
  }

  let claims;
  try {
    claims = verifyApproovToken(token);
  } catch (error) {
    next(
      createUnauthorizedError('token_verification_failed', error.message)
    );
    return;
  }

  const bindingHeaders = normalizeBindingHeaders(route.bindingHeaders);
  if (tokenBindingEnabled && bindingHeaders.length > 0) {
    let bindingInput;
    try {
      bindingInput = constructTokenBindingInput(ctx.req, bindingHeaders);
    } catch (error) {
      next(error);
      return;
    }
    if (!isBindingValid(bindingInput, claims)) {
      next(createUnauthorizedError('binding_mismatch', 'Invalid token binding.'));
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

function constructTokenBindingInput(req, bindingHeaders) {
  if (!req || typeof req !== 'object' || !req.headers) {
    throw createHttpError(
      400,
      'invalid_request',
      'A valid HTTP request object is required for token binding validation.',
      { logSummary: 'invalid_request' }
    );
  }

  const values = [];
  for (const header of bindingHeaders) {
    const value = trimOrNull(headerValue(req.headers, header));
    if (!hasText(value)) {
      throw createUnauthorizedError(
        'missing_binding_header',
        `Missing binding header: ${header}.`
      );
    }
    values.push(value);
  }

  // Build a single string from header values in configured order.
  return values.join('');
}

function isBindingValid(bindingInput, claims) {
  if (typeof bindingInput !== 'string') {
    return false;
  }

  const expected = typeof claims.pay === 'string' ? claims.pay.trim() : '';
  if (!hasText(expected)) {
    return false;
  }

  const computed = generateTokenBindingHash(bindingInput);
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
    if (status === 200 || status >= 400) {
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

function runMiddleware(ctx, middlewares, handler, done) {
  let index = -1;
  const onComplete = typeof done === 'function' ? done : () => {};

  const dispatch = (error) => {
    if (error) {
      onComplete(error);
      return;
    }

    index += 1;
    if (index > middlewares.length) {
      onComplete(
        createHttpError(
          500,
          'server_error',
          'Middleware called next() more than once.',
          { exposeMessage: false, logSummary: 'server_error' }
        )
      );
      return;
    }

    const current =
      index < middlewares.length ? middlewares[index] : handler;

    try {
      const result =
        index < middlewares.length ? current(ctx, dispatch) : current(ctx);

      if (result instanceof Error) {
        onComplete(result);
        return;
      }

      if (index >= middlewares.length) {
        onComplete();
      }
    } catch (caught) {
      onComplete(caught);
    }
  };

  dispatch();
}

function parseRequest(req) {
  const host = req.headers.host || `${SERVER_HOSTNAME}:${HTTP_PORT}`;
  let url;
  try {
    url = new URL(req.url || '/', `http://${host}`);
  } catch (error) {
    throw createHttpError(400, 'invalid_request', 'Invalid request URL.', {
      logSummary: 'invalid_request',
    });
  }
  return {
    path: url.pathname,
    method: (req.method || 'GET').toUpperCase(),
  };
}

function handleRequestError(ctx, error) {
  const appError = normalizeRequestError(error);
  if (hasText(appError.logSummary)) {
    ctx.state.logSummary = appError.logSummary;
  }

  if (ctx.res.headersSent) {
    return;
  }

  if (appError.statusCode >= 500) {
    console.error('Unhandled error:', error);
  }

  writeJson(ctx.res, appError.statusCode, {
    error: appError.code,
    message: appError.exposeMessage
      ? appError.message
      : 'Internal server error.',
  });
}

function normalizeRequestError(error) {
  if (error instanceof HttpError) {
    return error;
  }

  return createHttpError(500, 'server_error', 'Internal server error.', {
    exposeMessage: false,
    logSummary: 'server_error',
  });
}

function createUnauthorizedError(reason, message) {
  return createHttpError(401, 'unauthorized', message, {
    logSummary: `approov_failed:${reason}`,
    details: { reason },
  });
}

function createHttpError(statusCode, code, message, options) {
  return new HttpError(statusCode, code, message, options);
}

class HttpError extends Error {
  constructor(statusCode, code, message, options = {}) {
    super(message);
    this.name = 'HttpError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = options.details || null;
    this.logSummary = options.logSummary || null;
    this.exposeMessage = options.exposeMessage !== false;
  }
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

function generateTokenBindingHash(bindingInput) {
  if (typeof bindingInput !== 'string') {
    throw new TypeError('Token binding input must be a string.');
  }

  return crypto
    .createHash('sha256')
    .update(bindingInput, 'utf8')
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
