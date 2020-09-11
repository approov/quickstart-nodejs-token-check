const http = require('http');
const dotenv = require('dotenv').config()

if (dotenv.error) {
  console.debug('FAILED TO PARSE `.env` FILE | ' + dotenv.error)
}

// To run in a docker container add to the .env file `SERVER_HOSTNAME=0.0.0.0`.
const hostname = dotenv.parsed.SERVER_HOSTNAME || 'localhost';

// The port for the Quickstart Postman collection and cURL examples is 8002
const port = dotenv.parsed.HTTP_PORT || 8002;

const server = http.createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({message: "Hello, World!"}))
});

server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
