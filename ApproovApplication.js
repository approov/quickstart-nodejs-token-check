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
const ACCOUNT_SIGNATURE_MODE_ENABLED = parseBoolean(
  process.env.APPROOV_ENABLE_ACCOUNT_SIGNATURE ??
    process.env.APPROOV_ACCOUNT_SIGNATURE_ENABLED,
  false
);
const MESSAGE_SIGNATURE_MODE = ACCOUNT_SIGNATURE_MODE_ENABLED
  ? 'account'
  : 'install';

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
  SESSION_ID: 'session-id',
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
    method: 'POST',
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
    // Token binding can cover multiple headers. The bindingHeaders list is
    // concatenated (in order), hashed, and compared to the Approov token pay claim.
    bindingHeaders: [HEADER_NAMES.AUTHORIZATION],
  },
  {
    method: 'GET',
    path: '/token-double-binding',
    handler: tokenDoubleBindingHandler,
    requiresApproov: true,
    // Example of multi-header binding: Authorization + Session-Id.
    // Keep headers stable across requests; avoid Content-Digest because the body
    // can legitimately change and would invalidate the binding.
    bindingHeaders: [HEADER_NAMES.AUTHORIZATION, HEADER_NAMES.SESSION_ID],
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

/**
 * Handles the unauthenticated root endpoint used as a simple health check.
 * We keep this route outside Approov enforcement so operators can verify the
 * server is reachable without a valid Approov token or message signature.
 * The response mirrors the current port to make it clear which instance replied.
 */
function homeHandler(ctx) {
  writeJson(
    ctx.res,
    200,
    infoPayload(`Approov demo API is running on port ${HTTP_PORT}.`)
  );
}

/**
 * Returns the current in-memory enforcement toggles.
 * This is intended for demos/tests to confirm whether Approov checks and
 * token binding are enabled before running scripted requests.
 */
function approovStateHandler(ctx) {
  writeJson(ctx.res, 200, statePayload());
}

/**
 * Enables Approov token verification and token binding in one operation.
 * Approov is the primary access gate, so we also re-enable binding here to
 * keep the demo in a consistent "fully protected" state.
 */
function enableApproovHandler(ctx) {
  approovEnabled = true;
  tokenBindingEnabled = true;
  writeJson(ctx.res, 200, statePayload());
}

/**
 * Disables Approov token verification and binding.
 * This is a demo/testing switch only; in production you would not expose
 * an endpoint that bypasses token and binding checks.
 */
function disableApproovHandler(ctx) {
  approovEnabled = false;
  tokenBindingEnabled = false;
  writeJson(ctx.res, 200, statePayload());
}

/**
 * Enables token binding checks while leaving Approov token verification on.
 * Token binding proves possession of a client-bound value (for example an
 * Authorization header) that was hashed into the Approov token pay claim.
 */
function enableTokenBindingHandler(ctx) {
  tokenBindingEnabled = true;
  writeJson(ctx.res, 200, statePayload());
}

/**
 * Disables token binding checks while keeping Approov token verification on.
 * This is useful for testing that plain token validation still succeeds even
 * when the bound header is missing or intentionally mismatched.
 */
function disableTokenBindingHandler(ctx) {
  tokenBindingEnabled = false;
  writeJson(ctx.res, 200, statePayload());
}

/**
 * Demonstrates an endpoint that does not require Approov.
 * This is useful to show the contrast between protected and unprotected routes
 * when validating client integrations and automated tests.
 */
function unprotectedHandler(ctx) {
  writeJson(
    ctx.res,
    200,
    infoPayload("Unprotected endpoint '/unprotected'; no Approov checks performed.")
  );
}

/**
 * Basic Approov-protected endpoint.
 * The Approov middleware has already validated the JWT signature and exp claim
 * before this handler is invoked, so we simply return a success payload.
 */
function tokenCheckHandler(ctx) {
  writeJson(
    ctx.res,
    200,
    infoPayload("Protected endpoint '/token-check'; Approov token verified.")
  );
}

/**
 * Approov-protected endpoint that also requires HTTP Message Signatures.
 * This is the strictest path in the demo: it validates the Approov token and
 * then enforces a request signature bound to the Approov message-signing claims.
 */
function tokenCheckSignatureHandler(ctx) {
  writeJson(
    ctx.res,
    200,
    infoPayload(
      "Protected endpoint '/token-check-signature'; Approov token and message signature verified."
    )
  );
}

/**
 * Approov-protected endpoint that enforces token binding against Authorization.
 * We echo whether the Authorization header was present to make debugging
 * token binding and binding header selection easier during integration.
 */
function tokenBindingHandler(ctx) {
  const authorization = headerValue(ctx.headers, HEADER_NAMES.AUTHORIZATION);
  const response = infoPayload(
    "Protected endpoint '/token-binding'; Approov token binding enforced."
  );
  response.authorizationHeaderPresent = hasText(authorization);
  writeJson(ctx.res, 200, response);
}

/**
 * Approov-protected endpoint that enforces a composite binding.
 * The binding material is the Authorization header plus a stable Session-Id
 * header, which avoids coupling the binding to a mutable request body.
 */
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

/**
 * Middleware that enforces Approov token verification, optional token binding,
 * and optional HTTP Message Signatures depending on the current route.
 * Approov tokens are JWTs signed with a shared secret (HS256) and include
 * claims such as exp (expiry), ipk (install public key), and mskid (account key id).
 * Successful validation attaches the decoded claims to ctx.state for handlers.
 */
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

  // Binding headers are configured per-route so the server can bind different
  // endpoints to different header sets without hardcoding path checks.
  const bindingHeaders = normalizeBindingHeaders(route.bindingHeaders);
  if (tokenBindingEnabled && bindingHeaders.length > 0) {
    // Build the binding material by concatenating all required headers.
    // If any header is missing, we treat the binding as invalid.
    const bindingValue = extractBindingValue(ctx.headers, bindingHeaders);
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

/**
 * Validates the Approov JWT using the shared secret and standard JWT rules.
 * We explicitly require HS256 because Approov tokens in this demo are HMAC based
 * and rejecting other algorithms prevents algorithm substitution attacks.
 * The JWT signature is recomputed and compared using timing-safe equality, then
 * we enforce the exp claim to avoid accepting expired tokens.
 */
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

/**
 * Splits a JWT into header, payload, and signature and decodes the base64url parts.
 * We also return the signing input (header.payload) so HMAC verification can
 * be performed exactly as the token was produced.
 */
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

/**
 * Extracts the header material that was bound into the Approov token pay claim.
 * The binding is created by concatenating the configured headers (in order) and
 * hashing the result. This allows binding to multiple headers while keeping
 * the binding material stable across otherwise mutable request bodies.
 */
/**
 * Normalizes a route's bindingHeaders list into a clean array of header names.
 * This guards against undefined/null entries and trims whitespace so the
 * comparison is consistent.
 */
function normalizeBindingHeaders(bindingHeaders) {
  if (!Array.isArray(bindingHeaders)) {
    return [];
  }
  return bindingHeaders
    .map((header) => (typeof header === 'string' ? header.trim() : ''))
    .filter((header) => hasText(header));
}

/**
 * Builds the token binding material by concatenating the configured headers.
 * The Approov mobile SDK computes the hash of the same concatenation and stores
 * it in the JWT pay claim; we repeat the process server-side for verification.
 */
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

/**
 * Validates the token binding by comparing the pay claim with a hash of the
 * bound header value. Approov binding uses SHA-256 and base64 encoding, so we
 * compute the same and compare using timing-safe equality to reduce side-channels.
 */
function isBindingValid(bindingValue, claims) {
  const expected = typeof claims.pay === 'string' ? claims.pay.trim() : '';
  if (!hasText(expected)) {
    logVerbose(null, 'binding', 'token', 'Missing pay claim for token binding.');
    return false;
  }

  const computed = hashBase64(bindingValue);
  return safeStringEqual(expected, computed);
}

/**
 * Enforces Approov HTTP Message Signatures using RFC 9421 semantics.
 * The server runs in a single signature mode controlled by environment:
 * - install mode (default): verifies only the install signature entry.
 * - account mode: verifies only the account signature entry.
 * Signature headers are parsed as Structured Headers and verified with
 * http-message-signatures, including Content-Digest validation when present.
 */
async function verifyMessageSignatures(ctx, claims) {
  const signatureMode = MESSAGE_SIGNATURE_MODE;
  const accountKeyId = typeof claims.mskid === 'string' ? claims.mskid.trim() : '';
  const shouldVerifyInstall = signatureMode === 'install';
  const shouldVerifyAccount = signatureMode === 'account';
  const installPublicKey = shouldVerifyInstall
    ? loadInstallPublicKey(claims)
    : null;

  logVerbose(ctx, 'signature', 'mode', `Using ${signatureMode} signature mode.`);

  if (shouldVerifyInstall && !installPublicKey) {
    logVerbose(ctx, 'signature', 'install', 'Install mode enabled but ipk claim missing.');
    throw new Error('Install signature mode requires ipk claim.');
  }

  if (shouldVerifyAccount) {
    if (!hasText(accountKeyId)) {
      logVerbose(ctx, 'signature', 'account', 'Account mode enabled but mskid claim missing.');
      throw new Error('Account signature mode requires mskid claim.');
    }
    if (!APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET) {
      logVerbose(ctx, 'signature', 'fail', 'Account message signing secret not configured.');
      throw new Error('Account message signing secret not configured.');
    }
    if (hasText(APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID)) {
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
  }

  const signatureHeader = headerValue(ctx.headers, HEADER_NAMES.SIGNATURE);
  const signatureInputHeader = headerValue(ctx.headers, HEADER_NAMES.SIGNATURE_INPUT);
  if (!hasText(signatureHeader) || !hasText(signatureInputHeader)) {
    logVerbose(ctx, 'signature', 'fail', 'Missing Signature or Signature-Input header.');
    throw new Error('Missing Signature headers.');
  }

  const signatures = structuredHeaders.parseDictionary(signatureHeader);
  const signatureInputs = structuredHeaders.parseDictionary(signatureInputHeader);
  const hasInstallEntry = signatures.has('install') || signatureInputs.has('install');
  const hasAccountEntry = signatures.has('account') || signatureInputs.has('account');
  logVerbose(
    ctx,
    'signature',
    'headers',
    `Signature keys=${Array.from(signatures.keys()).join(',') || 'none'}; Signature-Input keys=${Array.from(signatureInputs.keys()).join(',') || 'none'}.`
  );

  if (hasText(headerValue(ctx.headers, HEADER_NAMES.CONTENT_DIGEST))) {
    await verifyContentDigest(ctx);
  }

  if (shouldVerifyInstall && hasAccountEntry) {
    logVerbose(ctx, 'signature', 'account', 'Account signature entry rejected in install mode.');
    throw new Error('Account signature is disabled.');
  }

  if (shouldVerifyAccount && hasInstallEntry) {
    logVerbose(ctx, 'signature', 'install', 'Install signature entry rejected in account mode.');
    throw new Error('Install signature is disabled.');
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
  }
}

/**
 * Loads the install public key from the Approov ipk claim.
 * The claim is a base64url-encoded SPKI DER key, which we convert to a KeyObject
 * so Node.js crypto can verify ECDSA signatures.
 */
function loadInstallPublicKey(claims) {
  const publicKeyB64 =
    typeof claims.ipk === 'string' ? claims.ipk.trim() : '';
  if (!hasText(publicKeyB64)) {
    return null;
  }
  return createPublicKeyFromValue(publicKeyB64, 'Approov install public key');
}

/**
 * Verifies a single Signature/Signature-Input entry by name (install or account).
 * We build a canonical request, pass the verification key and required params,
 * and rely on http-message-signatures to validate the signature base and params.
 * The tolerance parameter allows bounded clock skew for created/expires values.
 */
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

/**
 * Constructs a minimal request object for signature verification.
 * We re-serialize only the signature entry being verified to avoid interference
 * from unrelated signature keys and to mirror how the client produced the base.
 */
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

/**
 * Builds an absolute request URL for signature verification and logging.
 * HTTP Message Signatures can include derived components like @authority and
 * @target-uri, so we must reconstruct the public URL as seen by the client.
 * We honor X-Forwarded-* and RFC 7239 Forwarded headers to support proxies.
 */
function buildRequestUrl(req) {
  const forwardedProto = firstHeaderValue(req.headers['x-forwarded-proto']);
  const forwardedHost = firstHeaderValue(req.headers['x-forwarded-host']);
  const forwarded = firstHeaderValue(req.headers['forwarded']);
  const forwardedHostFromForwarded = parseForwardedParam(forwarded, 'host');

  let scheme = forwardedProto;
  if (!scheme && forwarded) {
    const forwardedProtoFromForwarded = parseForwardedParam(forwarded, 'proto');
    if (forwardedProtoFromForwarded) {
      scheme = forwardedProtoFromForwarded;
    }
  }
  if (!scheme) {
    scheme = req.socket && req.socket.encrypted ? 'https' : 'http';
  }

  const host =
    forwardedHost ||
    forwardedHostFromForwarded ||
    req.headers.host ||
    `${SERVER_HOSTNAME}:${HTTP_PORT}`;
  return `${scheme}://${host}${req.url || '/'}`;
}

/**
 * Validates the Content-Digest header (RFC 9530) against the request body.
 * This ensures payload integrity and is required when the signature input
 * references content-digest or when clients include it for additional safety.
 */
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

/**
 * Reads and caches the request body so multiple consumers can access it.
 * We store both the Promise and the resolved buffer to avoid double-reading
 * the stream when verifying Content-Digest and when logging HTTP exchanges.
 */
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

/**
 * Ensures the Approov token has a valid exp claim and is not expired.
 * Approov tokens are time-bound, so exp must be in seconds since epoch and
 * strictly greater than the current time to be accepted.
 */
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

/**
 * Builds a standard response fragment describing enforcement state.
 * This keeps demo handlers consistent and makes responses easier to parse in tests.
 */
function statePayload() {
  return {
    approovEnabled,
    tokenBindingEnabled,
  };
}

/**
 * Adds a human-friendly detail string to the standard state payload.
 * This helps demo clients confirm which endpoint they hit and which checks ran.
 */
function infoPayload(details) {
  return {
    ...statePayload(),
    details,
  };
}

/**
 * Reads the Approov token from the expected header.
 * Approov SDKs send the token as "Approov-Token" which Node exposes lowercased.
 */
function readApproovToken(headers) {
  return trimOrNull(headerValue(headers, HEADER_NAMES.APPROOV_TOKEN));
}

/**
 * Normalizes header values that may be arrays in Node.js.
 * For our purposes we only care about the first header value.
 */
function headerValue(headers, name) {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Runs middleware in sequence, similar to a tiny Koa-style dispatcher.
 * Each middleware receives a next() function it must await to continue the chain.
 */
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

/**
 * Extracts path and method for routing.
 * We build a URL using the Host header so relative URLs can be parsed reliably.
 */
function parseRequest(req) {
  const host = req.headers.host || `${SERVER_HOSTNAME}:${HTTP_PORT}`;
  const url = new URL(req.url || '/', `http://${host}`);
  return {
    path: url.pathname,
    method: (req.method || 'GET').toUpperCase(),
  };
}

/**
 * Sends a consistent 401 JSON response for authentication failures.
 * This keeps error handling predictable for demo clients and scripts.
 */
function unauthorized(res, message) {
  writeJson(res, 401, { error: 'unauthorized', message });
}

/**
 * Serializes and writes JSON with standard headers.
 * Content-Length is set to avoid chunked encoding surprises in simple clients.
 */
function writeJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-cache',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

/**
 * Computes an HMAC-SHA256 signature of the JWT signing input.
 * Approov tokens in this demo are HS256, so this reproduces the expected signature.
 */
function signHmac(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest();
}

/**
 * Hashes a string with SHA-256 and returns base64 output.
 * Approov token binding uses this exact hash+base64 format for the pay claim.
 */
function hashBase64(value) {
  return crypto
    .createHash('sha256')
    .update(value, 'utf8')
    .digest('base64');
}

/**
 * Compares two buffers using timing-safe equality.
 * This avoids leaking partial match information when verifying signatures.
 */
function bufferEquals(left, right) {
  if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right)) {
    return false;
  }
  if (left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

/**
 * Performs a timing-safe comparison of two non-empty strings.
 * Empty values are rejected to avoid false positives in security checks.
 */
function safeStringEqual(left, right) {
  if (!hasText(left) || !hasText(right)) {
    return false;
  }
  return bufferEquals(Buffer.from(left), Buffer.from(right));
}

/**
 * Parses a JSON string with a clearer error message on failure.
 * This is used for JWT header and payload decoding to produce precise errors.
 */
function parseJson(value, label) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`Approov token ${label} is not valid JSON.`);
  }
}

/**
 * Decodes a base64url string to UTF-8 text.
 * JWT header and payload sections are base64url-encoded JSON.
 */
function base64UrlDecodeToString(value) {
  return base64UrlDecodeToBuffer(value).toString('utf8');
}

/**
 * Decodes a base64url string into a Buffer.
 * We normalize URL-safe characters and apply required padding before decoding.
 */
function base64UrlDecodeToBuffer(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    '='
  );
  return Buffer.from(padded, 'base64');
}

/**
 * Writes verbose, contextual logs when enabled.
 * We include the method/path prefix to tie logs back to a specific request.
 */
function logVerbose(ctx, area, step, message) {
  if (!VERBOSE_LOGGING) {
    return;
  }
  const prefix = ctx ? `[${ctx.method} ${ctx.path}]` : '[Approov]';
  console.log(`${prefix} ${area}:${step} ${message}`);
}

/**
 * Logs structured details of the Signature-Input entry.
 * This helps debug which components and parameters were used in the signature base.
 */
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

/**
 * Computes and logs a hash of the signature base for debugging.
 * Comparing this value with the client helps diagnose canonicalization mismatches.
 */
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

/**
 * Wraps the response stream to capture and log full HTTP exchanges.
 * This is intended for debugging message signing and payload digest mismatches.
 */
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

/**
 * Logs the request/response pair with headers and bodies.
 * Uses buildRequestUrl to reflect the public URL used for signature verification.
 */
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

/**
 * Normalizes response chunks into Buffer form.
 * This keeps logging code simple regardless of whether chunks are strings or Buffers.
 */
function toBuffer(chunk, encoding) {
  if (Buffer.isBuffer(chunk)) {
    return chunk;
  }
  if (typeof chunk === 'string') {
    return Buffer.from(chunk, encoding);
  }
  return Buffer.from(String(chunk));
}

/**
 * Parses a parameter from the RFC 7239 Forwarded header.
 * We only inspect the first Forwarded entry because it represents the client-facing hop.
 */
function parseForwardedParam(forwardedValue, key) {
  if (!hasText(forwardedValue) || !hasText(key)) {
    return null;
  }

  const targetKey = key.toLowerCase();
  const entry = forwardedValue.split(',')[0];
  const pairs = entry.split(';');
  for (const pair of pairs) {
    const trimmed = pair.trim();
    if (!trimmed) {
      continue;
    }
    const index = trimmed.indexOf('=');
    if (index <= 0) {
      continue;
    }
    const paramKey = trimmed.slice(0, index).trim().toLowerCase();
    if (paramKey !== targetKey) {
      continue;
    }
    let value = trimmed.slice(index + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    return value;
  }
  return null;
}

/**
 * Returns the first header value from a potentially comma-separated list.
 * Proxies often append values; we only use the first for scheme/host reconstruction.
 */
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

/**
 * Converts a PEM or base64url-encoded SPKI key into a KeyObject.
 * Approov ipk claims are DER-encoded keys, while some tooling may supply PEM.
 */
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

/**
 * Loads the account-level message signing secret from environment variables.
 * Approov supports raw, base64, or base64url encodings; we accept all three for
 * flexibility and exit early if decoding fails to avoid silent misconfiguration.
 */
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

/**
 * Parses a port number with a safe fallback.
 * Invalid input returns the default to keep the demo server predictable.
 */
function parsePort(value, fallback) {
  if (!hasText(value)) {
    return fallback;
  }
  const port = Number.parseInt(value, 10);
  return Number.isFinite(port) ? port : fallback;
}

/**
 * Parses a non-negative integer with a fallback.
 * Used for configurable tolerance values such as message-signing clock skew.
 */
function parsePositiveInt(value, fallback) {
  if (!hasText(value)) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

/**
 * Parses common boolean environment values (true/false, 1/0, yes/no, on/off).
 * Unrecognized values fall back to the provided default.
 */
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

/**
 * Returns true when a value is a non-empty, non-whitespace string.
 * This is used throughout to validate required configuration and headers.
 */
function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Trims a string or returns null for null/undefined.
 * This keeps header handling uniform without adding special-case checks.
 */
function trimOrNull(value) {
  return value == null ? null : value.trim();
}

/**
 * Minimal .env loader used instead of dotenv to keep the example self-contained.
 * We avoid overwriting existing process.env values so explicit environment
 * configuration takes precedence over the local file.
 */
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
