"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveComponent = deriveComponent;
exports.extractHeader = extractHeader;
exports.createSignatureBase = createSignatureBase;
exports.formatSignatureBase = formatSignatureBase;
exports.createSigningParameters = createSigningParameters;
exports.augmentHeaders = augmentHeaders;
exports.signMessage = signMessage;
exports.verifyMessage = verifyMessage;
const structured_headers_1 = require("structured-headers");
const structured_header_1 = require("../structured-header");
const types_1 = require("../types");
const errors_1 = require("../errors");
/**
 * Derives a component value defined by HTTP Message Signatures (RFC 9421).
 * Components like @method, @authority, and @target-uri are canonicalized inputs
 * to the signature base. Approov uses this machinery to validate that a client
 * signed the exact request metadata it sent, including method and target URL.
 *
 * Note: derived components can be bound to the associated request when signing
 * responses (using the "req" parameter), which is why we accept both message
 * and request objects.
 */
function deriveComponent(component, params, message, req) {
    // switch the context of the signing data depending on if the `req` flag was passed
    const context = params.has('req') ? req : message;
    if (!context) {
        throw new Error('Missing request in request-response bound component');
    }
    switch (component) {
        case '@method':
            if (!(0, types_1.isRequest)(context)) {
                throw new Error('Cannot derive @method from response');
            }
            return [context.method.toUpperCase()];
        case '@target-uri': {
            if (!(0, types_1.isRequest)(context)) {
                throw new Error('Cannot derive @target-uri on response');
            }
            return [context.url.toString()];
        }
        case '@authority': {
            if (!(0, types_1.isRequest)(context)) {
                throw new Error('Cannot derive @authority on response');
            }
            const { port, protocol, hostname } = typeof context.url === 'string' ? new URL(context.url) : context.url;
            let authority = hostname.toLowerCase();
            if (port && (protocol === 'http:' && port !== '80' || protocol === 'https:' && port !== '443')) {
                authority += `:${port}`;
            }
            return [authority];
        }
        case '@scheme': {
            if (!(0, types_1.isRequest)(context)) {
                throw new Error('Cannot derive @scheme on response');
            }
            const { protocol } = typeof context.url === 'string' ? new URL(context.url) : context.url;
            return [protocol.slice(0, -1)];
        }
        case '@request-target': {
            if (!(0, types_1.isRequest)(context)) {
                throw new Error('Cannot derive @request-target on response');
            }
            const { pathname, search } = typeof context.url === 'string' ? new URL(context.url) : context.url;
            // this is really sketchy because the request-target is actually what is in the raw HTTP header
            // so one should avoid signing this value as the application layer just can't know how this
            // is formatted
            return [`${pathname}${search}`];
        }
        case '@path': {
            if (!(0, types_1.isRequest)(context)) {
                throw new Error('Cannot derive @scheme on response');
            }
            const { pathname } = typeof context.url === 'string' ? new URL(context.url) : context.url;
            // https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-2.2.6
            // empty path means use `/`
            return [pathname || '/'];
        }
        case '@query': {
            if (!(0, types_1.isRequest)(context)) {
                throw new Error('Cannot derive @scheme on response');
            }
            const { search } = typeof context.url === 'string' ? new URL(context.url) : context.url;
            // https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#section-2.2.7
            // absent query params means use `?`
            return [search || '?'];
        }
        case '@query-param': {
            if (!(0, types_1.isRequest)(context)) {
                throw new Error('Cannot derive @scheme on response');
            }
            const { searchParams } = typeof context.url === 'string' ? new URL(context.url) : context.url;
            if (!params.has('name')) {
                throw new Error('@query-param must have a named parameter');
            }
            const name = decodeURIComponent(params.get('name').toString());
            if (!searchParams.has(name)) {
                throw new Error(`Expected query parameter "${name}" not found`);
            }
            return searchParams.getAll(name).map((value) => encodeURIComponent(value));
        }
        case '@status': {
            if ((0, types_1.isRequest)(context)) {
                throw new Error('Cannot obtain @status component for requests');
            }
            return [context.status.toString()];
        }
        default:
            throw new Error(`Unsupported component "${component}"`);
    }
}
/**
 * Extracts and canonicalizes a header value for the signature base.
 * Supports structured-field parsing ("sf"/"key" parameters) and binary
 * serialization ("bs" parameter) as described by RFC 9421.
 * Approov signatures commonly include headers like "approov-token" or
 * "content-digest", so this logic must preserve their exact semantics.
 */
function extractHeader(header, params, { headers }, req) {
    const context = params.has('req') ? req?.headers : headers;
    if (!context) {
        throw new Error('Missing request in request-response bound component');
    }
    const headerTuple = Object.entries(context).find(([name]) => name.toLowerCase() === header);
    if (!headerTuple) {
        throw new Error(`No header "${header}" found in headers`);
    }
    const values = (Array.isArray(headerTuple[1]) ? headerTuple[1] : [headerTuple[1]]);
    if (params.has('bs') && (params.has('sf') || params.has('key'))) {
        throw new Error('Cannot have both `bs` and (implicit) `sf` parameters');
    }
    if (params.has('sf') || params.has('key')) {
        // strict encoding of field
        const value = values.join(', ');
        const parsed = (0, structured_header_1.parseHeader)(value);
        if (params.has('key') && !(parsed instanceof structured_header_1.Dictionary)) {
            throw new Error('Unable to parse header as dictionary');
        }
        if (params.has('key')) {
            const key = params.get('key').toString();
            if (!parsed.has(key)) {
                throw new Error(`Unable to find key "${key}" in structured field`);
            }
            return [parsed.get(key)];
        }
        return [parsed.toString()];
    }
    if (params.has('bs')) {
        return [values.map((val) => {
                const encoded = Buffer.from(val.trim().replace(/\n\s*/gm, ' '));
                return `:${encoded.toString('base64')}:`;
            }).join(', ')];
    }
    // raw encoding
    return [values.map((val) => val.trim().replace(/\n\s*/gm, ' ')).join(', ')];
}
/**
 * Normalizes structured-header parameter values into primitives.
 * The signature base requires deterministic formatting, so ByteSequence and
 * Token instances are converted to their string forms before use.
 */
function normaliseParams(params) {
    const map = new Map;
    params.forEach((value, key) => {
        if (value instanceof structured_headers_1.ByteSequence) {
            map.set(key, value.toBase64());
        }
        else if (value instanceof structured_headers_1.Token) {
            map.set(key, value.toString());
        }
        else {
            map.set(key, value);
        }
    });
    return map;
}
/**
 * Builds the ordered signature base (list of component/value pairs).
 * Each field is parsed as a structured item, then expanded into a concrete
 * value derived from the request/response or headers. Approov relies on this
 * canonical base to validate that a signed request was not tampered with.
 */
function createSignatureBase(config, res, req) {
    return (config.fields).reduce((base, fieldName) => {
        const [field, params] = (0, structured_headers_1.parseItem)((0, structured_header_1.quoteString)(fieldName));
        const fieldParams = normaliseParams(params);
        const lcFieldName = field.toLowerCase();
        if (lcFieldName !== '@signature-params') {
            let value = null;
            if (config.componentParser) {
                value = config.componentParser(lcFieldName, fieldParams, res, req) ?? null;
            }
            if (value === null) {
                value = field.startsWith('@') ? deriveComponent(lcFieldName, fieldParams, res, req) : extractHeader(lcFieldName, fieldParams, res, req);
            }
            base.push([(0, structured_headers_1.serializeItem)([field, params]), value]);
        }
        return base;
    }, []);
}
/**
 * Formats the signature base into the canonical string for signing/verifying.
 * Each line is "<quoted-field>: <value>" and the final string is what gets
 * signed or verified by the cryptographic algorithm.
 */
function formatSignatureBase(base) {
    return base.map(([key, value]) => {
        const quotedKey = (0, structured_headers_1.serializeItem)((0, structured_headers_1.parseItem)((0, structured_header_1.quoteString)(key)));
        return value.map((val) => `${quotedKey}: ${val}`).join('\n');
    }).join('\n');
}
/**
 * Produces the signature parameters (created, expires, keyid, alg, etc).
 * These parameters are embedded in the Signature-Input header and are part of
 * the signature base. Approov clients and servers must agree on their values
 * to validate message signatures.
 */
function createSigningParameters(config) {
    const now = new Date();
    return (config.params ?? types_1.defaultParams).reduce((params, paramName) => {
        let value = '';
        switch (paramName.toLowerCase()) {
            case 'created':
                // created is optional but recommended. If created is supplied but is null, that's an explicit
                // instruction to *not* include the created parameter
                if (config.paramValues?.created !== null) {
                    const created = config.paramValues?.created ?? now;
                    value = Math.floor(created.getTime() / 1000);
                }
                break;
            case 'expires':
                // attempt to obtain an explicit expires time, otherwise create one that is 300 seconds after
                // creation. Don't add an expires time if there is no created time
                if (config.paramValues?.expires || config.paramValues?.created !== null) {
                    const expires = config.paramValues?.expires ?? new Date((config.paramValues?.created ?? now).getTime() + 300000);
                    value = Math.floor(expires.getTime() / 1000);
                }
                break;
            case 'keyid': {
                // attempt to obtain the keyid omit if missing
                const kid = config.paramValues?.keyid ?? config.key.id ?? null;
                if (kid) {
                    value = kid.toString();
                }
                break;
            }
            case 'alg': {
                // if there is no alg, but it's listed as a required parameter, we should probably
                // throw an error - the problem is that if it's in the default set of params, do we
                // really want to throw if there's no keyid?
                const alg = config.paramValues?.alg ?? config.key.alg ?? null;
                if (alg) {
                    value = alg.toString();
                }
                break;
            }
            default:
                if (config.paramValues?.[paramName] instanceof Date) {
                    value = Math.floor(config.paramValues[paramName].getTime() / 1000);
                }
                else if (config.paramValues?.[paramName]) {
                    value = config.paramValues[paramName];
                }
        }
        if (value) {
            params.set(paramName, value);
        }
        return params;
    }, new Map());
}
/**
 * Inserts or appends Signature and Signature-Input headers onto a message.
 * When existing signatures are present, we preserve their names and add a
 * unique suffix so multiple signatures can coexist on the same request.
 */
function augmentHeaders(headers, signature, signatureInput, name) {
    let signatureHeaderName = 'Signature';
    let signatureInputHeaderName = 'Signature-Input';
    let signatureHeader = new Map();
    let inputHeader = new Map();
    // check to see if there are already signature/signature-input headers
    // if there are we want to store the current (case-sensitive) name of the header
    // and we want to parse out the current values so we can append our new signature
    for (const header in headers) {
        switch (header.toLowerCase()) {
            case 'signature': {
                signatureHeaderName = header;
                signatureHeader = (0, structured_headers_1.parseDictionary)(Array.isArray(headers[header]) ? headers[header].join(', ') : headers[header]);
                break;
            }
            case 'signature-input':
                signatureInputHeaderName = header;
                inputHeader = (0, structured_headers_1.parseDictionary)(Array.isArray(headers[header]) ? headers[header].join(', ') : headers[header]);
                break;
        }
    }
    // find a unique signature name for the header. Check if any existing headers already use
    // the name we intend to use, if there are, add incrementing numbers to the signature name
    // until we have a unique name to use
    let signatureName = name ?? 'sig';
    if (signatureHeader.has(signatureName) || inputHeader.has(signatureName)) {
        let count = 0;
        while (signatureHeader.has(`${signatureName}${count}`) || inputHeader.has(`${signatureName}${count}`)) {
            count++;
        }
        signatureName += count.toString();
    }
    // append our signature and signature-inputs to the headers and return
    signatureHeader.set(signatureName, [new structured_headers_1.ByteSequence(signature.toString('base64')), new Map()]);
    inputHeader.set(signatureName, (0, structured_headers_1.parseList)(signatureInput)[0]);
    return {
        ...headers,
        [signatureHeaderName]: (0, structured_headers_1.serializeDictionary)(signatureHeader),
        [signatureInputHeaderName]: (0, structured_headers_1.serializeDictionary)(inputHeader),
    };
}
/**
 * High-level signing helper: builds the signature base, signs it, and returns
 * a new message with updated Signature/Signature-Input headers. Approov SDKs
 * use this flow to attach message signatures to outbound requests.
 */
async function signMessage(config, message, req) {
    const signingParameters = createSigningParameters(config);
    const signatureBase = createSignatureBase({
        fields: config.fields ?? [],
        componentParser: config.componentParser,
    }, message, req);
    const signatureInput = (0, structured_headers_1.serializeList)([
        [
            signatureBase.map(([item]) => (0, structured_headers_1.parseItem)(item)),
            signingParameters,
        ],
    ]);
    signatureBase.push(['"@signature-params"', [signatureInput]]);
    const base = formatSignatureBase(signatureBase);
    // call sign
    const signature = await config.key.sign(Buffer.from(base));
    return {
        ...message,
        headers: augmentHeaders({ ...message.headers }, signature, signatureInput, config.name),
    };
}
/**
 * High-level verification helper: parses signature headers, validates required
 * parameters and fields, rebuilds the signature base, and verifies the crypto.
 * Returns null when no signature headers exist, true/false when verification
 * succeeds/fails, or throws when the signature is malformed.
 */
async function verifyMessage(config, message, req) {
    const { signatures, signatureInputs } = Object.entries(message.headers).reduce((accum, [name, value]) => {
        switch (name.toLowerCase()) {
            case 'signature':
                return Object.assign(accum, {
                    signatures: (0, structured_headers_1.parseDictionary)(Array.isArray(value) ? value.join(', ') : value),
                });
            case 'signature-input':
                return Object.assign(accum, {
                    signatureInputs: (0, structured_headers_1.parseDictionary)(Array.isArray(value) ? value.join(', ') : value),
                });
            default:
                return accum;
        }
    }, {});
    // no signatures means an indeterminate result
    if (!signatures?.size && !signatureInputs?.size) {
        return null;
    }
    // a missing header means we can't verify the signatures
    if (!signatures?.size || !signatureInputs?.size) {
        throw new Error('Incomplete signature headers');
    }
    const now = Math.floor(Date.now() / 1000);
    const tolerance = config.tolerance ?? 0;
    const notAfter = config.notAfter instanceof Date ? Math.floor(config.notAfter.getTime() / 1000) : config.notAfter ?? now;
    const maxAge = config.maxAge ?? null;
    const requiredParams = config.requiredParams ?? [];
    const requiredFields = config.requiredFields ?? [];
    return Array.from(signatureInputs.entries()).reduce(async (prev, [name, input]) => {
        const signatureParams = Array.from(input[1].entries()).reduce((params, [key, value]) => {
            if (value instanceof structured_headers_1.ByteSequence) {
                Object.assign(params, {
                    [key]: value.toBase64(),
                });
            }
            else if (value instanceof structured_headers_1.Token) {
                Object.assign(params, {
                    [key]: value.toString(),
                });
            }
            // Vendored bug note: this repo previously normalized "expired" instead of
            // the RFC 9421 "expires" parameter. We now accept both for backward
            // compatibility and to avoid breaking clients that relied on the bug.
            else if (key === 'created' || key === 'expires' || key === 'expired') {
                Object.assign(params, {
                    [key]: new Date(value * 1000),
                });
            }
            else {
                Object.assign(params, {
                    [key]: value,
                });
            }
            return params;
        }, {});
        const [result, key] = await Promise.all([
            prev.catch((e) => e),
            config.keyLookup(signatureParams),
        ]);
        // @todo - confirm this is all working as expected
        if (config.all && !key) {
            throw new errors_1.UnknownKeyError('Unknown key');
        }
        if (!key) {
            if (result instanceof Error) {
                throw result;
            }
            return result;
        }
        if (input[1].has('alg') && key.algs?.includes(input[1].get('alg')) === false) {
            throw new errors_1.UnsupportedAlgorithmError('Unsupported key algorithm');
        }
        if (!(0, structured_headers_1.isInnerList)(input)) {
            throw new errors_1.MalformedSignatureError('Malformed signature input');
        }
        const hasRequiredParams = requiredParams.every((param) => input[1].has(param));
        if (!hasRequiredParams) {
            throw new errors_1.UnacceptableSignatureError('Missing required signature parameters');
        }
        // this could be tricky, what if we say "@method" but there is "@method;req"
        const hasRequiredFields = requiredFields.every((field) => input[0].some(([fieldName]) => fieldName === field));
        if (!hasRequiredFields) {
            throw new errors_1.UnacceptableSignatureError('Missing required signed fields');
        }
        if (input[1].has('created')) {
            const created = input[1].get('created') - tolerance;
            // maxAge overrides expires.
            // signature is older than maxAge
            if ((maxAge && now - created > maxAge) || created > notAfter) {
                throw new errors_1.ExpiredError('Signature is too old');
            }
        }
        if (input[1].has('expires')) {
            const expires = input[1].get('expires') + tolerance;
            // expired signature
            if (now > expires) {
                throw new errors_1.ExpiredError('Signature has expired');
            }
        }
        // now look to verify the signature! Build the expected "signing base" and verify it!
        const fields = input[0].map((item) => (0, structured_headers_1.serializeItem)(item));
        const signingBase = createSignatureBase({ fields, componentParser: config.componentParser }, message, req);
        signingBase.push(['"@signature-params"', [(0, structured_headers_1.serializeList)([input])]]);
        const base = formatSignatureBase(signingBase);
        const signature = signatures.get(name);
        if (!signature) {
            throw new errors_1.MalformedSignatureError('No corresponding signature for input');
        }
        if (!(0, structured_headers_1.isByteSequence)(signature[0])) {
            throw new errors_1.MalformedSignatureError('Malformed signature');
        }
        return key.verify(Buffer.from(base), Buffer.from(signature[0].toBase64(), 'base64'), signatureParams);
    }, Promise.resolve(null));
}
//# sourceMappingURL=index.js.map
