const http = require('http');
const dotenv = require('dotenv').config()
const jwt = require('jsonwebtoken')


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
    console.debug("Missing Approov token")
    return false
  }

  // decode token, verify secret and check exp
  return jwt.verify(appoovToken, approovSecret, { algorithms: ['HS256'] }, function(err, decoded) {

    if (err) {
      // You may want to add some logging here.
      console.debug("Approov token error: " + err)
      return false
    }

    // The Approov token was successfully verified. We will add the claims to
    // the request object to allow further use of them during the request
    // processing.
    req.approovTokenClaims = decoded

    return true
  })
}

const server = http.createServer((req, res) => {

  console.debug("<--- / GET")

  res.setHeader('Content-Type', 'application/json');

  if (!verifyApproovToken(req)) {
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
