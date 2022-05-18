# Ethereal Secrets Server

A standalone ethereal secrets server showcasing the usage of the middleware.

## Quickstart

Start a standalone ethereal secrets server along with a redis server:

```sh
$ docker network create ethereal-secrets-example
$ docker run --rm -d --network ethereal-secrets-example --name redis redis
$ docker run --rm -d --network ethereal-secrets-example  --name ethereal-secrets-server -p 8080:8080 neoskop/ethereal-secrets-server
```

Alternatively you can use docker-compose:

```sh
$ docker-compose up
```

To check the server is working correctly you can access http://localhost:8080/ which will start a new session and create a key for you:

```sh
$ curl http://localhost:8080/ 2>/dev/null | jq -r .key
HXBIeiJogIXH7dxJBPPLbcvL7ecJgCMTZqWkKDfZ1HA=
```
