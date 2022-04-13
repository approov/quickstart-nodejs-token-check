# Approov Integrations Examples

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps, and here you can find the Hello servers examples that are the base for the Approov [quickstarts](/docs) for NodeJS.

For more information about how Approov works and why you should use it you can read the [Approov Overview](/OVERVIEW.md) at the root of this repo.

If you are looking for the Approov quickstarts to integrate Approov in your NodeJS API server then you can find them [here](/QUICKSTARTS.md).


## Hello Server Examples

To learn more about each Hello server example you need to read the README for each one at:

* [Unprotected Server](./src/unprotected-server)
* [Approov Protected Server - Token Check](./src/approov-protected-server/token-check)
* [Approov Protected Server - Token Binding Check](./src/approov-protected-server/token-binding-check)


## Docker Stack

The docker stack provided via the `docker-compose.yml` file in this folder is used for development proposes and if you are familiar with docker then feel free to also use it to follow along the examples on the README of each server.

If you decide to use the docker stack then you need to bear in mind that the Postman collections, used to test the servers examples, will connect to port `8002` therefore you cannot start all docker compose services at once, for example with `docker-compose up`, instead you need to run one at a time as exemplified below.

### Setup Env File

Do not forget to properly setup the `.env` file in the root of each Approov protected server example before you run the server with the docker stack.

```bash
cp src/unprotected-server/.env.example src/unprotected-server/.env
cp src/approov-protected-server/token-check/.env.example src/approov-protected-server/token-check/.env
cp src/approov-protected-server/token-binding-check/.env.example src/approov-protected-server/token-binding-check/.env
```

Edit each file and add the [dummy secret](/TESTING.md#the-dummy-secret) to it in order to be able to test the Approov integration with the provided [Postman collection](https://github.com/approov/postman-collections/blob/master/quickstarts/hello-world/hello-world.postman_curl_requests_examples.md).


### Build the Docker Stack

The three services in the `docker-compose.yml` use the same Dockerfile, therefore to build the Docker image we just need to used one of them:

```bash
sudo docker-compose build approov-token-binding-check
```

Now, you are ready to start using the Docker stack for NodeJS.


### Command Examples

To run each of the Hello servers with docker compose you just need to follow the respective example below.

#### For the unprotected server

Run the container attached to your machine bash shell:

```bash
sudo docker-compose up unprotected-server
```

or get a bash shell inside the container:

```bash
sudo docker-compose run --rm --service-ports unprotected-server zsh
```

#### For the Approov Token Check

Run the container attached to the shell:

```bash
sudo docker-compose up approov-token-check
```

or get a bash shell inside the container:

```bash
sudo docker-compose run --rm --service-ports approov-token-check zsh
```

#### For the Approov Token Binding Check

Run the container attached to the shell:

```bash
sudo docker-compose up approov-token-binding-check
```

or get a bash shell inside the container:

```bash
sudo docker-compose run --rm --service-ports approov-token-binding-check zsh
```


## Issues

If you find any issue while following the example then just open an issue on this repo with the steps to reproduce it and we will help you to solve them.


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
