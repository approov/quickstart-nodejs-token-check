const http = require('http');
const dotenv = require('dotenv').config()
const jwt = require('jsonwebtoken')
const crypto = require('crypto')

if (dotenv.error) {
  console.debug('FAILED TO PARSE `.env` FILE | ' + dotenv.error)
}

// To run in a docker container add to the .env file `SERVER_HOSTNAME=0.0.0.0`.
const hostname = dotenv.parsed.SERVER_HOSTNAME || 'localhost';

// The port for the Quickstart Postman collection and cURL examples is 8002
const port = dotenv.parsed.HTTP_PORT || 8002;

const approovBase64Secret = dotenv.parsed.APPROOV_BASE64_SECRET;

const approovSecret = Buffer.from(approovBase64Secret, 'base64')

const verifyApproovToken = function(req) {

  const appoovToken = req.headers['approov-token']

  if (!appoovToken) {
    // You may want to add some logging here.
    return false
  }

  // decode token, verify secret and check exp
  return jwt.verify(appoovToken, approovSecret, { algorithms: ['HS256'] }, function(err, decoded) {

    if (err) {
      // You may want to add some logging here.
      return false
    }

    // The Approov token was successfully verified. We will add the claims to
    // the request object to allow further use of them during the request
    // processing.
    req.approovTokenClaims = decoded

    return true
  })
}

const verifyApproovTokenBinding = function(req) {

  // Note that the `pay` claim will, under normal circumstances, be present,
  // but if the Approov failover system is enabled, then no claim will be
  // present, and in this case you want to return true, otherwise you will not
  // be able to benefit from the redundancy afforded by the failover system.
  if (!("pay" in req.approovTokenClaims)) {
    // You may want to add some logging here.
    return true
  }

  // The Approov token claims is added to the request object on a successful
  //  Approov token verification. See `verifyApproovToken()` function.
  token_binding_claim = req.approovTokenClaims.pay

  // We use here the Authorization token, but feel free to use another header,
  // but you need to bind this header to the Approov token in the mobile app.
  token_binding_header = req.headers['authorization']

  if (!token_binding_header) {
    // You may want to add some logging here.
    return false
  }

  // We need to hash and base64 encode the token binding header, because thats
  // how it was included in the Approov token on the mobile app.
  const token_binding_header_encoded = crypto.createHash('sha256').update(token_binding_header, 'utf-8').digest('base64')

  return token_binding_claim === token_binding_header_encoded
}

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');

  if (!verifyApproovToken(req)) {
    res.statusCode = 401
    res.end(JSON.stringify({}))
    return
  }

  if (!verifyApproovTokenBinding(req)) {
    res.statusCode = 401
    res.end(JSON.stringify({}))
    return
  }

  res.statusCode = 200;
  res.end(JSON.stringify({message: "Hello, World!"}))
});

server.listen(port, hostname, () => {
  console.log(`Approov protected server running at http://${hostname}:${port}/`);
});
