'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { httpbis, createVerifier } = require('./vendor/http-message-signatures/lib');
const structuredHeaders = require('./vendor/http-message-signatures/node_modules/structured-headers');

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

const APPROOV_ACCOUNT_PUBLIC_KEY_BASE64 =
  process.env.APPROOV_ACCOUNT_PUBLIC_KEY_BASE64 ||
  process.env.APPROOV_ACCOUNT_PUBLIC_KEY;

const MESSAGE_SIGNING_TOLERANCE_SECONDS = parsePositiveInt(
  process.env.APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS,
  60
);

const MESSAGE_SIGNING_ALGORITHM = 'ecdsa-p256-sha256';

const MESSAGE_SIGNING_REQUIRED_PARAMS = Object.freeze([
  'alg',
  'created',
  'expires',
]);

const APPROOV_ACCOUNT_PUBLIC_KEY = loadPublicKey(
  APPROOV_ACCOUNT_PUBLIC_KEY_BASE64,
  'APPROOV_ACCOUNT_PUBLIC_KEY_BASE64'
);

let approovEnabled = true;
let tokenBindingEnabled = true;

const HEADER_NAMES = Object.freeze({
  APPROOV_TOKEN: 'approov-token',
  AUTHORIZATION: 'authorization',
  CONTENT_DIGEST: 'content-digest',
  SIGNATURE: 'signature',
  SIGNATURE_INPUT: 'signature-input',
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
    path: '/token-check-signature',
    handler: tokenCheckSignatureHandler,
    requiresApproov: true,
    requiresMessageSignature: true,
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

  runMiddleware(ctx, MIDDLEWARE, route.handler).catch((error) => {
    console.error('Unhandled error:', error);
    if (!res.writableEnded) {
      writeJson(res, 500, { error: 'server_error' });
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

function tokenCheckSignatureHandler(ctx) {
  writeJson(
    ctx.res,
    200,
    infoPayload(
      "Protected endpoint '/token-check-signature'; Approov token and message signature verified."
    )
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

async function approovTokenVerifier(ctx, next) {
  const route = ctx.route;
  if (!route || !route.requiresApproov) {
    await next();
    return;
  }

  if (!approovEnabled) {
    await next();
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

  if (route.requiresMessageSignature) {
    try {
      await verifyMessageSignatures(ctx, claims);
    } catch (error) {
      unauthorized(ctx.res, error.message);
      return;
    }
  }

  ctx.state.approovClaims = claims;
  await next();
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

async function verifyMessageSignatures(ctx, claims) {
  const installPublicKey = loadInstallPublicKey(claims);
  const accountPublicKey = APPROOV_ACCOUNT_PUBLIC_KEY;

  if (!installPublicKey && !accountPublicKey) {
    return;
  }

  const signatureHeader = headerValue(ctx.headers, HEADER_NAMES.SIGNATURE);
  const signatureInputHeader = headerValue(ctx.headers, HEADER_NAMES.SIGNATURE_INPUT);
  if (!hasText(signatureHeader) || !hasText(signatureInputHeader)) {
    throw new Error('Missing Signature headers.');
  }

  const signatures = structuredHeaders.parseDictionary(signatureHeader);
  const signatureInputs = structuredHeaders.parseDictionary(signatureInputHeader);

  if (hasText(headerValue(ctx.headers, HEADER_NAMES.CONTENT_DIGEST))) {
    await verifyContentDigest(ctx);
  }

  if (installPublicKey) {
    await verifySignatureEntry(
      ctx,
      signatures,
      signatureInputs,
      'install',
      installPublicKey
    );
  }

  if (accountPublicKey) {
    await verifySignatureEntry(
      ctx,
      signatures,
      signatureInputs,
      'account',
      accountPublicKey
    );
  }
}

function loadInstallPublicKey(claims) {
  const publicKeyB64 =
    typeof claims.ipk === 'string' ? claims.ipk.trim() : '';
  if (!hasText(publicKeyB64)) {
    return null;
  }
  return createPublicKeyFromValue(publicKeyB64, 'Approov install public key');
}

async function verifySignatureEntry(
  ctx,
  signatures,
  signatureInputs,
  signatureName,
  publicKey
) {
  const signatureEntry = signatures.get(signatureName);
  const signatureInputEntry = signatureInputs.get(signatureName);

  if (!signatureEntry || !signatureInputEntry) {
    throw new Error(`Missing ${signatureName} signature entry.`);
  }

  const signatureHeader = structuredHeaders.serializeDictionary(
    new Map([[signatureName, signatureEntry]])
  );
  const signatureInputHeader = structuredHeaders.serializeDictionary(
    new Map([[signatureName, signatureInputEntry]])
  );

  const verified = await httpbis.verifyMessage(
    {
      keyLookup: async () => ({
        id: signatureName,
        algs: [MESSAGE_SIGNING_ALGORITHM],
        verify: createVerifier(publicKey, MESSAGE_SIGNING_ALGORITHM),
      }),
      requiredParams: MESSAGE_SIGNING_REQUIRED_PARAMS,
      tolerance: MESSAGE_SIGNING_TOLERANCE_SECONDS,
    },
    buildSignatureRequest(ctx, signatureHeader, signatureInputHeader)
  );

  if (verified !== true) {
    throw new Error(`Invalid ${signatureName} message signature.`);
  }
}

function buildSignatureRequest(ctx, signatureHeader, signatureInputHeader) {
  return {
    method: ctx.method,
    url: buildRequestUrl(ctx.req),
    headers: {
      ...ctx.headers,
      [HEADER_NAMES.SIGNATURE]: signatureHeader,
      [HEADER_NAMES.SIGNATURE_INPUT]: signatureInputHeader,
    },
  };
}

function buildRequestUrl(req) {
  const host = req.headers.host || `${SERVER_HOSTNAME}:${HTTP_PORT}`;
  const scheme = req.socket && req.socket.encrypted ? 'https' : 'http';
  return `${scheme}://${host}${req.url || '/'}`;
}

async function verifyContentDigest(ctx) {
  const header = headerValue(ctx.headers, HEADER_NAMES.CONTENT_DIGEST);
  if (!hasText(header)) {
    return;
  }

  const digestEntries = structuredHeaders.parseDictionary(header);
  if (!digestEntries || digestEntries.size === 0) {
    throw new Error('Content-Digest header is empty.');
  }

  const body = await readRequestBody(ctx);

  for (const [algo, [item]] of digestEntries.entries()) {
    const normalizedAlgo = algo.toLowerCase();
    const hashAlgo =
      normalizedAlgo === 'sha-256'
        ? 'sha256'
        : normalizedAlgo === 'sha-512'
          ? 'sha512'
          : null;

    if (!hashAlgo) {
      throw new Error(`Unsupported content digest algorithm: ${algo}.`);
    }

    let expectedDigest;
    if (item instanceof structuredHeaders.ByteSequence) {
      expectedDigest = item.toBase64();
    } else if (typeof item === 'string') {
      expectedDigest = item;
    } else {
      throw new Error(`Unsupported Content-Digest value for ${algo}.`);
    }

    const computedDigest = crypto
      .createHash(hashAlgo)
      .update(body)
      .digest('base64');

    if (!safeStringEqual(expectedDigest, computedDigest)) {
      throw new Error(`Content digest verification failed for ${algo}.`);
    }
  }
}

async function readRequestBody(ctx) {
  if (ctx.state.bodyBuffer) {
    return ctx.state.bodyBuffer;
  }

  const bodyBuffer = await new Promise((resolve, reject) => {
    const chunks = [];
    ctx.req.on('data', (chunk) => {
      chunks.push(chunk);
    });
    ctx.req.on('end', () => resolve(Buffer.concat(chunks)));
    ctx.req.on('error', reject);
  });

  ctx.state.bodyBuffer = bodyBuffer;
  return bodyBuffer;
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

async function runMiddleware(ctx, middlewares, handler) {
  let index = -1;

  const dispatch = async () => {
    index += 1;
    const fn = index < middlewares.length ? middlewares[index] : handler;
    if (!fn) {
      return;
    }
    await fn(ctx, dispatch);
  };

  await dispatch();
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

function createPublicKeyFromValue(value, label) {
  const trimmed = value.trim();
  try {
    if (trimmed.includes('-----BEGIN')) {
      return crypto.createPublicKey(trimmed);
    }
    const der = base64UrlDecodeToBuffer(trimmed);
    return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`);
  }
}

function loadPublicKey(value, label) {
  if (!hasText(value)) {
    return null;
  }
  try {
    return createPublicKeyFromValue(value, label);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

function parsePort(value, fallback) {
  if (!hasText(value)) {
    return fallback;
  }
  const port = Number.parseInt(value, 10);
  return Number.isFinite(port) ? port : fallback;
}

function parsePositiveInt(value, fallback) {
  if (!hasText(value)) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
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
