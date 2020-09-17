# Approov Token Binding Integration Example

This Approov integration example is from where the code example for the [Approov token binding check quickstart](/docs/APPROOV_TOKEN_BINDING_QUICKSTART.md) is extracted, and you can use it as a playground to better understand how simple and easy it is to implement [Approov](https://approov.io) in a NodeJS API server.


## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try the Approov Integration Example](#try-the-approov-integration-example)


## Why?

To lock down your API server to your mobile app. Please read the brief summary in the [README](/README.md#why) at the root of this repo or visit our [website](https://approov.io/product.html) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The NodeJS server is very simple and is defined in the file [src/approov-protected-server/token-binding-check/hello-server-protected.js](src/approov-protected-server/token-binding-check/hello-server-protected.js). Take a look at the `verifyApproovToken()` and `verifyApproovTokenBinding()` functions to see the simple code for the checks.

For more background on Approov, see the overview in the [README](/README.md#how-it-works) at the root of this repo.

[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have NodeJS installed. If you don't have then please follow the official installation instructions from [here](https://nodejs.org/en/download/) to download and install it.

[TOC](#toc---table-of-contents)


## Try the Approov Integration Example

First, you need to set the dummy secret in the `src/approov-protected-server/token-binding-check/.env` file as explained [here](/README.md#the-dummy-secret).

Second, you need to install the dependencies. From the `src/approov-protected-server/token-binding-check` folder execute:

```text
npm install
```

Now, you can run this example from the `src/approov-protected-server/token-binding-check` folder with:

```text
npm start
```

Finally, you can test that the Approov integration example works as expected with this [Postman collection](/README.md#testing-with-postman) or with some cURL requests [examples](/README.md#testing-with-curl).

[TOC](#toc---table-of-contents)
