# Approov QuickStart - NodeJS Token Check

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps.

This repo implements the Approov server-side request verification code in NodeJS (framework agnostic), which performs the verification check before allowing valid traffic to be processed by the API endpoint.


## Approov Integration Quickstart

The quickstart was tested with the following Operating Systems:

* Ubuntu 20.04
* MacOS Big Sur
* Windows 10 WSL2 - Ubuntu 20.04

First, setup the [Appoov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli).

Now, register the API domain for which Approov will issues tokens:

```bash
approov api -add api.example.com
```

Next, enable your Approov `admin` role with:

```bash
eval `approov role admin`
````

Now, get your Approov Secret with the [Appoov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli):

```bash
approov secret -get base64
```

Next, add the [Approov secret](https://approov.io/docs/latest/approov-usage-documentation/#account-secret-key-export) to your project `.env` file:

```env
APPROOV_BASE64_SECRET=approov_base64_secret_here
```

Now, add to your `package.json` file the [JWT dependency](https://github.com/auth0/node-jsonwebtoken#readme):

```json
"jsonwebtoken": "^8.5.1"
```

Next, in your code require the [JWT dependency](https://github.com/auth0/node-jsonwebtoken#readme):

```javascript
const jwt = require('jsonwebtoken')
```

Now, grab the Approov secret into a constant:

```javascript
const dotenv = require('dotenv').config()
const approovBase64Secret = dotenv.parsed.APPROOV_BASE64_SECRET;
const approovSecret = Buffer.from(approovBase64Secret, 'base64')
```

Next, verify the Approov token:

```javascript
const verifyApproovToken = function(req) {

  const appoovToken = req.headers['approov-token']

  if (!appoovToken) {
    // You may want to add some logging here.
    return false
  }

  // Decode the token with strict verification of the signature (['HS256']) to
  // prevent against the `none` algorithm attack.
  return jwt.verify(appoovToken, approovSecret, { algorithms: ['HS256'] }, function(err, decoded) {

    if (err) {
      // You may want to add some logging here.
      return false
    }

    // The Approov token was successfully verified. We will add the claims to the
    // request object to allow further use of them during the request processing.
    req.approovTokenClaims = decoded

    return true
  })
}
```

Finally, invoke the check for each API endpoint you want to protect with Approov:

```javascript
if (!verifyApproovToken(req)) {
  res.statusCode = 401
  res.end(JSON.stringify({}))
  return
}
```

Not enough details in the bare bones quickstart? No worries, check the [detailed quickstarts](QUICKSTARTS.md) that contain a more comprehensive set of instructions, including how to test the Approov integration.


## More Information

* [Approov Overview](OVERVIEW.md)
* [Detailed Quickstarts](QUICKSTARTS.md)
* [Examples](EXAMPLES.md)
* [Testing](TESTING.md)

### System Clock

In order to correctly check for the expiration times of the Approov tokens is very important that the backend server is synchronizing automatically the system clock over the network with an authoritative time source. In Linux this is usually done with a NTP server.


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-nodejs-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov Get Started](https://approov.io/product/demo)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://approov.io/blog/)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.zendesk.com/hc/en-gb/requests/new)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)
