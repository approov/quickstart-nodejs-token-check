"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultParams = void 0;
exports.isRequest = isRequest;
/**
 * Default parameters to use when signing a request if none are supplied by the consumer
 */
exports.defaultParams = [
    'keyid',
    'alg',
    'created',
    'expires',
];
function isRequest(obj) {
    return !!obj.method;
}
//# sourceMappingURL=index.js.map