# Unprotected Server Example

The unprotected example is the base reference to build the [Approov protected servers](/src/approov-protected-server/). This a very basic Hello World server.


## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try It](#try-it)


## Why?

To be the starting building block for the [Approov protected servers](/src/approov-protected-server/), that will show you how to lock down your API server to your mobile app. Please read the brief summary in the [README](/README.md#why) at the root of this repo or visit our [website](https://approov.io/product.html) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The NodeJS server is very simple and is defined in the file [src/unprotected-server/hello-server-unprotected.js](/src/unprotected-server/hello-server-unprotected.js).

The server only replies to the endpoint `/` with the message:

```json
{"message": "Hello, World!"}
```

[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have NodeJS installed. If you don't have then please follow the official installation instructions from [here](https://nodejs.org/en/download/) to download and install it.

[TOC](#toc---table-of-contents)


## Try It

First install the dependencies. From the `src/unprotected-server` folder execute:

```text
npm install
```

Now, you can run this example from the `src/unprotected-server` folder with:

```text
npm start
```

Finally, you can test that it works with:

```text
curl -iX GET 'http://localhost:8002'
```

The response will be:

```text
HTTP/1.1 200 OK
Content-Type: application/json
Date: Tue, 08 Sep 2020 16:05:53 GMT
Content-Length: 28

{"message": "Hello, World!"}
```

[TOC](#toc---table-of-contents)
