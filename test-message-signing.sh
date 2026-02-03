#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

#######################################
# Approov message signing tests.
#
# Description:
#   Generates a valid Approov token with an ipk claim and a matching
#   HTTP message signature, then exercises /token-check-signature with
#   curl requests.
#
# Dependencies:
#   - bash
#   - curl
#   - node (>=18)
#
# Environment:
#   BASE_URL:
#     Base URL of the API under test. Default: http://localhost:8111
#   TOKDIR:
#     Directory where temporary token files are stored. Default: .config
#   APPROOV_BASE64URL_SECRET:
#     Approov shared secret (base64url).
#######################################

readonly BASE_URL="${BASE_URL:-http://localhost:8111}"
readonly TOKDIR="${TOKDIR:-.config}"
readonly LOGDIR="${TOKDIR}/logs"
readonly LOGFILE="${LOGDIR}/message-signing-$(date '+%Y-%m-%d_%H-%M-%S').log"

success_code=200
failure_code=401
is_approov_disabled=false

err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

requirement_check() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    err "Missing required command: ${cmd}"
    exit 1
  fi
}

load_env() {
  if [[ ! -f ".env" ]]; then
    return
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    local trimmed
    trimmed="$(echo "${line}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [[ -z "${trimmed}" || "${trimmed}" == \#* ]]; then
      continue
    fi
    if [[ "${trimmed}" != *"="* ]]; then
      continue
    fi
    local key="${trimmed%%=*}"
    local value="${trimmed#*=}"
    key="$(echo "${key}" | sed -e 's/[[:space:]]*$//')"
    value="$(echo "${value}" | sed -e 's/^[[:space:]]*//')"
    if [[ "${value}" =~ ^\".*\"$ || "${value}" =~ ^\'.*\'$ ]]; then
      value="${value:1:${#value}-2}"
    fi
    export "${key}=${value}"
  done < ".env"
}

print_test_result() {
  local name="$1"
  local expected="$2"
  local status="$3"
  local resp="$4"

  local result="Failed"
  if [[ "${status}" == "${expected}" ]]; then
    result="Passed"
  fi

  echo "${name}: ${result}  (status: ${status}, expected: ${expected})"

  {
    echo "Test: ${name}"
    echo "Expected status: ${expected}"
    echo "Actual status:   ${status}"
    if [[ "${is_approov_disabled}" == "false" ]]; then
      echo "Approov State: enabled, token checks performed."
    else
      echo "Approov State: disabled, no checks performed."
    fi
    echo
    echo "HTTP exchange:"
    echo "${resp}"
    echo
  } >>"${LOGFILE}" 2>&1
}

run_test() {
  local name="$1"; shift
  local expected="$1"; shift

  local resp
  local status
  local curl_rc

  set +o errexit
  resp="$(curl -i -s "$@")"
  curl_rc=$?
  set -o errexit

  if ((curl_rc != 0)); then
    err "curl failed for ${name} (rc=${curl_rc})"
    return "${curl_rc}"
  fi

  status="$(
    printf '%s\n' "${resp}" |
      grep -m1 '^HTTP/' |
      awk '{print $2}'
  )"

  print_test_result "${name}" "${expected}" "${status}" "${resp}"
}

generate_message_signature_payload() {
  env BASE_URL="${BASE_URL}" node <<'NODE'
const crypto = require('crypto');
const { httpbis, createSigner } = require('./vendor/http-message-signatures/lib');

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    '='
  );
  return Buffer.from(padded, 'base64');
}

function toBase64Url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function signJwtHS256(secret, header, payload) {
  const headerB64 = toBase64Url(header);
  const payloadB64 = toBase64Url(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest('base64url');
  return `${signingInput}.${signature}`;
}

const secretB64 = process.env.APPROOV_BASE64URL_SECRET;
if (!secretB64) {
  console.error('APPROOV_BASE64URL_SECRET not set');
  process.exit(1);
}
const secret = base64UrlDecode(secretB64.trim());

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
});
const ipk = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

const now = Math.floor(Date.now() / 1000);
const header = { alg: 'HS256', typ: 'JWT' };
const payload = {
  aud: '',
  exp: now + 600,
  iat: now,
  ip: '1.2.3.4',
  did: 'ExampleApproovTokenDID==',
  ipk,
};
const token = signJwtHS256(secret, header, payload);

const signer = createSigner(privateKey, 'ecdsa-p256-sha256');
const request = {
  method: 'GET',
  url: `${process.env.BASE_URL}/token-check-signature`,
  headers: {
    'approov-token': token,
  },
};

httpbis.signMessage(
  {
    key: signer,
    name: 'install',
    fields: ['@method', 'approov-token'],
  },
  request
).then((signed) => {
  const signatureHeader = signed.headers['signature'] || signed.headers['Signature'];
  const signatureInputHeader = signed.headers['signature-input'] || signed.headers['Signature-Input'];
  console.log(token);
  console.log(signatureHeader);
  console.log(signatureInputHeader);
  console.log(ipk);
}).catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
NODE
}

main() {
  requirement_check "curl"
  requirement_check "node"

  load_env

  if [[ -z "${APPROOV_BASE64URL_SECRET:-}" ]]; then
    err "APPROOV_BASE64URL_SECRET is not set (check .env)."
    exit 1
  fi

  if [[ -n "${APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64URL:-}" || -n "${APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_BASE64:-}" || -n "${APPROOV_ACCOUNT_MESSAGE_SIGNING_SECRET_RAW:-}" || -n "${APPROOV_ACCOUNT_MESSAGE_SIGNING_KEY_ID:-}" ]]; then
    err "Account message signing env is set; this script only signs the install key."
    err "Unset it or extend the script to sign account signatures as well."
    exit 1
  fi

  mkdir -p "${TOKDIR}" "${LOGDIR}"

  echo "Approov state check:"
  local state_response
  state_response="$(curl -i -s "${BASE_URL}/approov-state")"
  local state_http_code
  state_http_code="$(
    printf '%s\n' "${state_response}" |
      grep -m1 '^HTTP/' |
      awk '{print $2}'
  )"

  if [[ "${state_http_code}" != "200" || -z "${state_http_code}" ]]; then
    err "Failed to get Approov state from ${BASE_URL}/approov-state (status=${state_http_code:-unknown})"
    exit 1
  fi

  if grep -q '"approovEnabled":true' <<<"${state_response}"; then
    echo " Approov service: ENABLED"
    is_approov_disabled=false
  else
    echo " Approov service: DISABLED"
    is_approov_disabled=true
    failure_code=200
  fi
  echo

  local generated=()
  local line
  while IFS= read -r line; do
    generated+=("${line}")
  done < <(generate_message_signature_payload)

  if [[ "${#generated[@]}" -lt 3 ]]; then
    err "Failed to generate message signature payload."
    exit 1
  fi

  local token="${generated[0]}"
  local signature_header="${generated[1]}"
  local signature_input_header="${generated[2]}"

  run_test \
    "Message signature - valid install signature" \
    "${success_code}" \
    -H "Approov-Token: ${token}" \
    -H "Signature: ${signature_header}" \
    -H "Signature-Input: ${signature_input_header}" \
    "${BASE_URL}/token-check-signature"

  run_test \
    "Message signature - missing signature headers" \
    "${failure_code}" \
    -H "Approov-Token: ${token}" \
    "${BASE_URL}/token-check-signature"

  local sig_prefix="install=:"
  local sig_suffix=":"
  local sig_b64="${signature_header#${sig_prefix}}"
  sig_b64="${sig_b64%${sig_suffix}}"
  local tampered_sig_b64="${sig_b64/a/b}"
  if [[ "${tampered_sig_b64}" == "${sig_b64}" ]]; then
    tampered_sig_b64="A${sig_b64:1}"
  fi
  local tampered_signature="${sig_prefix}${tampered_sig_b64}${sig_suffix}"

  run_test \
    "Message signature - invalid signature bytes" \
    "${failure_code}" \
    -H "Approov-Token: ${token}" \
    -H "Signature: ${tampered_signature}" \
    -H "Signature-Input: ${signature_input_header}" \
    "${BASE_URL}/token-check-signature"

  local tampered_token
  tampered_token="${token}x"

  run_test \
    "Message signature - invalid token signature" \
    "${failure_code}" \
    -H "Approov-Token: ${tampered_token}" \
    -H "Signature: ${signature_header}" \
    -H "Signature-Input: ${signature_input_header}" \
    "${BASE_URL}/token-check-signature"

  echo
  echo "Full request and response details are saved in:"
  echo "  ${LOGFILE}"
}

main "$@"
