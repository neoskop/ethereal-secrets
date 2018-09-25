# Ethereal Secrets Client #

## Usage ##

To add the library to your project:

```sh
$ npm i --save @neoskop/ethereal-secrets-client
```

to store a value `bar` under the key `foo` encrypted in the session storage:

```typescript
let client = new EtherealSecretsClient({
  endpoint: 'http://localhost:8080/secrets'
});
client.setItem('foo', 'bar');
client.getItem('foo'); // => bar
client.removeItem('foo');
```

## Test suite ##

To run integration tests in case you checked out the repository (awesome!):

```sh
$ docker pull neoskop/ethereal-secrets-server && docker-compose -f docker-compose.test.yml up --abort-on-container-exit --build
```
