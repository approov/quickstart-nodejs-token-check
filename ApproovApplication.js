'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { httpbis, createVerifier } = require('./vendor/http-message-signatures/lib');
const structuredHeaders = require('./vendor/http-message-signatures/node_modules/structured-headers');

loadEnvFile(path.join(__dirname, '.env'));

const SERVER_HOSTNAME = process.env.SERVER_HOSTNAME || 'localhost';
const HTTP_PORT = parsePort(process.env.HTTP_PORT, 8111);

const APPROOV_SECRET_BASE64URL =
  process.env.APPROOV_BASE64URL_SECRET || process.env.APPROOV_BASE64_SECRET;

if (!hasText(APPROOV_SECRET_BASE64URL)) {
  console.error('APPROOV_BASE64URL_SECRET environment variable is not set');
  process.exit(1);
}

const APPROOV_SECRET = base64UrlDecodeToBuffer(APPROOV_SECRET_BASE64URL.trim());

const APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64URL =
  process.env.APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64URL ||
  process.env.APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET;
const APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64 =
  process.env.APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64;
const APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_RAW =
  process.env.APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_RAW;
const APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID =
  process.env.APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID;

const MESSAGE_SIGNING_TOLERANCE_SECONDS = parsePositiveInt(
  process.env.APPROOV_MESSAGE_SIGNING_TOLERANCE_SECONDS,
  60
);

const INSTALL_MESSAGE_SIGNING_ALGORITHM = 'ecdsa-p256-sha256';
const ACCOUNT_MESSAGE_SIGNING_ALGORITHM = 'hmac-sha256';

const MESSAGE_SIGNING_REQUIRED_PARAMS = Object.freeze([
  'alg',
  'created',
  'expires',
]);

const VERBOSE_LOGGING = parseBoolean(process.env.APPROOV_VERBOSE_LOGGING, true);
const HTTP_LOGGING_ENABLED = parseBoolean(
  process.env.APPROOV_HTTP_LOGGING,
  false
);

const APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET = loadAccountMessageSigningSecret();

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

  if (HTTP_LOGGING_ENABLED) {
    enableHttpLogging(ctx);
    readRequestBody(ctx).catch((error) => {
      logVerbose(ctx, 'http', 'body', `Failed to read body: ${error.message}`);
    });
  }

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
    logVerbose(ctx, 'approov', 'skip', 'Route does not require Approov.');
    await next();
    return;
  }

  if (!approovEnabled) {
    logVerbose(ctx, 'approov', 'skip', 'Approov checks disabled.');
    await next();
    return;
  }

  logVerbose(ctx, 'approov', 'start', 'Approov verification started.');
  const token = readApproovToken(ctx.headers);
  if (!hasText(token)) {
    logVerbose(ctx, 'approov', 'fail', 'Missing Approov-Token header.');
    unauthorized(ctx.res, 'Missing Approov-Token header.');
    return;
  }

  let claims;
  try {
    claims = verifyApproovToken(token);
    logVerbose(
      ctx,
      'approov',
      'token',
      `Token verified (exp=${claims.exp ?? 'n/a'}; ipk=${hasText(claims.ipk ? String(claims.ipk) : '')}; mskid=${claims.mskid ?? 'n/a'}).`
    );
  } catch (error) {
    logVerbose(ctx, 'approov', 'fail', `Token verification failed: ${error.message}`);
    unauthorized(ctx.res, error.message);
    return;
  }

  if (tokenBindingEnabled && needsBindingCheck(route.path)) {
    const bindingValue = extractBindingValue(route.path, ctx.headers);
    if (!hasText(bindingValue) || !isBindingValid(bindingValue, claims)) {
      logVerbose(ctx, 'binding', 'fail', 'Token binding validation failed.');
      unauthorized(ctx.res, 'Invalid token binding.');
      return;
    }
    logVerbose(ctx, 'binding', 'ok', 'Token binding validation passed.');
  }

  if (route.requiresMessageSignature) {
    try {
      logVerbose(ctx, 'signature', 'start', 'Message signature verification started.');
      await verifyMessageSignatures(ctx, claims);
      logVerbose(ctx, 'signature', 'ok', 'Message signature verification passed.');
    } catch (error) {
      logVerbose(ctx, 'signature', 'fail', `Message signature verification failed: ${error.message}`);
      unauthorized(ctx.res, error.message);
      return;
    }
  } else {
    logVerbose(ctx, 'signature', 'skip', 'Route does not require message signing.');
  }

  ctx.state.approovClaims = claims;
  logVerbose(ctx, 'approov', 'done', 'Approov verification completed.');
  await next();
}

function verifyApproovToken(token) {
  const parsed = parseJwt(token);

  if (parsed.header.alg !== 'HS256') {
    logVerbose(null, 'approov', 'token', `Rejected token alg=${parsed.header.alg || 'unknown'}.`);
    throw new Error(`Unsupported token alg: ${parsed.header.alg || 'unknown'}.`);
  }

  const expectedSignature = signHmac(parsed.signingInput, APPROOV_SECRET);
  if (!bufferEquals(expectedSignature, parsed.signature)) {
    logVerbose(null, 'approov', 'token', 'Token signature mismatch.');
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
    logVerbose(null, 'binding', 'token', 'Missing pay claim for token binding.');
    return false;
  }

  const computed = hashBase64(bindingValue);
  return safeStringEqual(expected, computed);
}

async function verifyMessageSignatures(ctx, claims) {
  const installPublicKey = loadInstallPublicKey(claims);
  const accountKeyId = typeof claims.mskid === 'string' ? claims.mskid.trim() : '';
  const shouldVerifyInstall = !!installPublicKey;
  const shouldVerifyAccount = !shouldVerifyInstall && hasText(accountKeyId);

  if (!shouldVerifyInstall && !shouldVerifyAccount) {
    logVerbose(ctx, 'signature', 'skip', 'No install ipk or account key id available.');
    return;
  }

  if (shouldVerifyAccount && !APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET) {
    logVerbose(ctx, 'signature', 'fail', 'Account message signing secret not configured.');
    throw new Error('Account message signing secret not configured.');
  }

  if (shouldVerifyAccount && hasText(APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID)) {
    if (APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID !== accountKeyId) {
      logVerbose(
        ctx,
        'signature',
        'account',
        `Account key id mismatch (expected=${APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID}, got=${accountKeyId}).`
      );
      throw new Error('Account message signing key id mismatch.');
    }
  }

  const signatureHeader = headerValue(ctx.headers, HEADER_NAMES.SIGNATURE);
  const signatureInputHeader = headerValue(ctx.headers, HEADER_NAMES.SIGNATURE_INPUT);
  if (!hasText(signatureHeader) || !hasText(signatureInputHeader)) {
    logVerbose(ctx, 'signature', 'fail', 'Missing Signature or Signature-Input header.');
    throw new Error('Missing Signature headers.');
  }

  const signatures = structuredHeaders.parseDictionary(signatureHeader);
  const signatureInputs = structuredHeaders.parseDictionary(signatureInputHeader);
  logVerbose(
    ctx,
    'signature',
    'headers',
    `Signature keys=${Array.from(signatures.keys()).join(',') || 'none'}; Signature-Input keys=${Array.from(signatureInputs.keys()).join(',') || 'none'}.`
  );

  if (hasText(headerValue(ctx.headers, HEADER_NAMES.CONTENT_DIGEST))) {
    await verifyContentDigest(ctx);
  }

  if (shouldVerifyInstall) {
    logVerbose(ctx, 'signature', 'install', 'Verifying install signature entry.');
    await verifySignatureEntry(
      ctx,
      signatures,
      signatureInputs,
      'install',
      installPublicKey,
      INSTALL_MESSAGE_SIGNING_ALGORITHM
    );
    if (hasText(accountKeyId)) {
      logVerbose(
        ctx,
        'signature',
        'account',
        'Skipping account signature because install ipk claim is present.'
      );
    }
  } else if (signatures.has('install')) {
    logVerbose(ctx, 'signature', 'install', 'Install signature present but ipk claim missing.');
  }

  if (shouldVerifyAccount) {
    logVerbose(ctx, 'signature', 'account', 'Verifying account signature entry.');
    await verifySignatureEntry(
      ctx,
      signatures,
      signatureInputs,
      'account',
      APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET,
      ACCOUNT_MESSAGE_SIGNING_ALGORITHM
    );
  } else if (signatures.has('account')) {
    logVerbose(ctx, 'signature', 'account', 'Account signature present but mskid claim missing.');
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
  verificationKey,
  algorithm
) {
  const signatureEntry = signatures.get(signatureName);
  const signatureInputEntry = signatureInputs.get(signatureName);

  if (!signatureEntry || !signatureInputEntry) {
    logVerbose(ctx, 'signature', signatureName, 'Signature entry missing.');
    throw new Error(`Missing ${signatureName} signature entry.`);
  }

  logSignatureInputDetails(ctx, signatureName, signatureInputEntry);

  const signatureHeader = structuredHeaders.serializeDictionary(
    new Map([[signatureName, signatureEntry]])
  );
  const signatureInputHeader = structuredHeaders.serializeDictionary(
    new Map([[signatureName, signatureInputEntry]])
  );

  const signatureRequest = buildSignatureRequest(
    ctx,
    signatureHeader,
    signatureInputHeader
  );
  logVerbose(ctx, 'signature', signatureName, `Request URL used: ${signatureRequest.url}`);
  logSignatureBaseHash(ctx, signatureName, signatureRequest, signatureInputEntry);

  const verified = await httpbis.verifyMessage(
    {
      keyLookup: async () => ({
        id: signatureName,
        algs: [algorithm],
        verify: createVerifier(verificationKey, algorithm),
      }),
      requiredParams: MESSAGE_SIGNING_REQUIRED_PARAMS,
      tolerance: MESSAGE_SIGNING_TOLERANCE_SECONDS,
    },
    signatureRequest
  );

  if (verified !== true) {
    logVerbose(ctx, 'signature', signatureName, 'Signature verification returned false.');
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
  const forwardedProto = firstHeaderValue(req.headers['x-forwarded-proto']);
  const forwardedHost = firstHeaderValue(req.headers['x-forwarded-host']);
  const forwarded = firstHeaderValue(req.headers['forwarded']);

  let scheme = forwardedProto;
  if (!scheme && forwarded) {
    const match = forwarded.match(/proto=([^;]+)/i);
    if (match) {
      scheme = match[1];
    }
  }
  if (!scheme) {
    scheme = req.socket && req.socket.encrypted ? 'https' : 'http';
  }

  const host = forwardedHost || req.headers.host || `${SERVER_HOSTNAME}:${HTTP_PORT}`;
  return `${scheme}://${host}${req.url || '/'}`;
}

async function verifyContentDigest(ctx) {
  const header = headerValue(ctx.headers, HEADER_NAMES.CONTENT_DIGEST);
  if (!hasText(header)) {
    return;
  }

  const digestEntries = structuredHeaders.parseDictionary(header);
  if (!digestEntries || digestEntries.size === 0) {
    logVerbose(ctx, 'digest', 'fail', 'Content-Digest header empty.');
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
      logVerbose(ctx, 'digest', 'fail', `Unsupported algorithm: ${algo}.`);
      throw new Error(`Unsupported content digest algorithm: ${algo}.`);
    }

    let expectedDigest;
    if (item instanceof structuredHeaders.ByteSequence) {
      expectedDigest = item.toBase64();
    } else if (typeof item === 'string') {
      expectedDigest = item;
    } else {
      logVerbose(ctx, 'digest', 'fail', `Unsupported Content-Digest value for ${algo}.`);
      throw new Error(`Unsupported Content-Digest value for ${algo}.`);
    }

    const computedDigest = crypto
      .createHash(hashAlgo)
      .update(body)
      .digest('base64');

    if (!safeStringEqual(expectedDigest, computedDigest)) {
      logVerbose(
        ctx,
        'digest',
        'fail',
        `Digest mismatch for ${algo} (expected=${expectedDigest}, computed=${computedDigest}).`
      );
      throw new Error(`Content digest verification failed for ${algo}.`);
    }
    logVerbose(ctx, 'digest', 'ok', `Digest matched for ${algo}.`);
  }
}

async function readRequestBody(ctx) {
  if (ctx.state.bodyBuffer) {
    return ctx.state.bodyBuffer;
  }
  if (ctx.state.bodyPromise) {
    return ctx.state.bodyPromise;
  }

  ctx.state.bodyPromise = new Promise((resolve, reject) => {
    const chunks = [];
    ctx.req.on('data', (chunk) => {
      chunks.push(chunk);
    });
    ctx.req.on('end', () => resolve(Buffer.concat(chunks)));
    ctx.req.on('error', reject);
  });

  const bodyBuffer = await ctx.state.bodyPromise;
  ctx.state.bodyBuffer = bodyBuffer;
  ctx.state.bodyPromise = null;
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

function logVerbose(ctx, area, step, message) {
  if (!VERBOSE_LOGGING) {
    return;
  }
  const prefix = ctx ? `[${ctx.method} ${ctx.path}]` : '[Approov]';
  console.log(`${prefix} ${area}:${step} ${message}`);
}

function logSignatureInputDetails(ctx, signatureName, signatureInputEntry) {
  if (!VERBOSE_LOGGING) {
    return;
  }
  if (!Array.isArray(signatureInputEntry) || signatureInputEntry.length < 2) {
    logVerbose(ctx, 'signature', signatureName, 'Signature input entry malformed.');
    return;
  }
  const components = signatureInputEntry[0] || [];
  const params = signatureInputEntry[1] || new Map();
  const componentNames = components.map(([name]) => name).join(',') || 'none';
  const paramPairs = Array.from(params.entries())
    .map(([key, value]) => `${key}=${value}`)
    .join(',') || 'none';
  logVerbose(
    ctx,
    'signature',
    signatureName,
    `Signature-Input components=[${componentNames}], params=[${paramPairs}].`
  );
}

function logSignatureBaseHash(ctx, signatureName, signatureRequest, signatureInputEntry) {
  if (!VERBOSE_LOGGING) {
    return;
  }
  try {
    if (!Array.isArray(signatureInputEntry) || signatureInputEntry.length < 2) {
      return;
    }
    const components = signatureInputEntry[0] || [];
    const fields = components.map((item) => structuredHeaders.serializeItem(item));
    const signatureBase = httpbis.createSignatureBase(
      { fields },
      signatureRequest
    );
    signatureBase.push([
      '"@signature-params"',
      [structuredHeaders.serializeList([signatureInputEntry])],
    ]);
    const base = httpbis.formatSignatureBase(signatureBase);
    const baseHash = crypto
      .createHash('sha256')
      .update(base)
      .digest('base64');
    logVerbose(
      ctx,
      'signature',
      signatureName,
      `Signature base sha256 (base64)=${baseHash}`
    );
  } catch (error) {
    logVerbose(
      ctx,
      'signature',
      signatureName,
      `Failed to compute signature base hash: ${error.message}`
    );
  }
}

function enableHttpLogging(ctx) {
  if (!HTTP_LOGGING_ENABLED) {
    return;
  }

  const startTime = Date.now();
  const responseChunks = [];
  const originalWrite = ctx.res.write.bind(ctx.res);
  const originalEnd = ctx.res.end.bind(ctx.res);

  ctx.res.write = (chunk, encoding, callback) => {
    if (chunk) {
      responseChunks.push(toBuffer(chunk, encoding));
    }
    return originalWrite(chunk, encoding, callback);
  };

  ctx.res.end = (chunk, encoding, callback) => {
    if (chunk) {
      responseChunks.push(toBuffer(chunk, encoding));
    }
    const responseBody = Buffer.concat(responseChunks);
    logHttpExchange(ctx, responseBody, startTime);
    return originalEnd(chunk, encoding, callback);
  };
}

function logHttpExchange(ctx, responseBody, startTime) {
  if (!HTTP_LOGGING_ENABLED) {
    return;
  }
  const durationMs = Date.now() - startTime;
  const requestBodyPromise =
    ctx.state.bodyPromise || Promise.resolve(ctx.state.bodyBuffer || Buffer.alloc(0));
  requestBodyPromise
    .then((requestBody) => {
      const requestUrl = buildRequestUrl(ctx.req);
      const responseHeaders = ctx.res.getHeaders();
      console.log('--- HTTP EXCHANGE START ---');
      console.log(`Request: ${ctx.method} ${requestUrl}`);
      console.log('Request Headers:', JSON.stringify(ctx.headers, null, 2));
      console.log('Request Body:', requestBody.toString('utf8'));
      console.log(`Response Status: ${ctx.res.statusCode}`);
      console.log('Response Headers:', JSON.stringify(responseHeaders, null, 2));
      console.log('Response Body:', responseBody.toString('utf8'));
      console.log(`Duration: ${durationMs}ms`);
      console.log('--- HTTP EXCHANGE END ---');
    })
    .catch((error) => {
      console.log('--- HTTP EXCHANGE START ---');
      console.log(`Request: ${ctx.method} ${ctx.path}`);
      console.log('Request Headers:', JSON.stringify(ctx.headers, null, 2));
      console.log(`Failed to read request body: ${error.message}`);
      console.log(`Response Status: ${ctx.res.statusCode}`);
      console.log('Response Headers:', JSON.stringify(ctx.res.getHeaders(), null, 2));
      console.log('Response Body:', responseBody.toString('utf8'));
      console.log(`Duration: ${durationMs}ms`);
      console.log('--- HTTP EXCHANGE END ---');
    });
}

function toBuffer(chunk, encoding) {
  if (Buffer.isBuffer(chunk)) {
    return chunk;
  }
  if (typeof chunk === 'string') {
    return Buffer.from(chunk, encoding);
  }
  return Buffer.from(String(chunk));
}

function firstHeaderValue(value) {
  if (!value) {
    return null;
  }
  const raw = Array.isArray(value) ? value[0] : value;
  if (!hasText(raw)) {
    return null;
  }
  return raw.split(',')[0].trim();
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

function loadAccountMessageSigningSecret() {
  const secretValue =
    APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64URL ||
    APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64 ||
    APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_RAW;

  if (!hasText(secretValue)) {
    return null;
  }

  try {
    if (APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_RAW) {
      return Buffer.from(APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_RAW, 'utf8');
    }
    if (APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64URL) {
      return base64UrlDecodeToBuffer(APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64URL);
    }
    return Buffer.from(APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64, 'base64');
  } catch (error) {
    console.error(`Account message signing secret is invalid: ${error.message}`);
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

function parseBoolean(value, fallback) {
  if (value == null) {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'y', 'on'].includes(normalized)) {
    return true;
  }
  if (['false', '0', 'no', 'n', 'off'].includes(normalized)) {
    return false;
  }
  return fallback;
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
