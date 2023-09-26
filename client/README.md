# Ethereal Secrets Client

## Usage

To add the library to your project:

```sh
$ npm i --save @neoskop/ethereal-secrets-client
```

### Local Mode

to store a value `bar` under the key `foo` encrypted in the session storage:

```typescript
const client = new EtherealSecretsClient({
  endpoint: 'http://localhost:8080/secrets',
});
await client.saveLocal('foo', 'bar');
await client.getLocal('foo'); // => bar
await client.removeLocal('foo');
```

### Remote Mode

To store a value `bar` encrypted on the server:

```typescript
const client = new EtherealSecretsClient({
  endpoint: 'http://localhost:8080/secrets',
});
const result = await client.saveRemote('foo', 'bar');
await client.getRemote(result.fragmentIdentifier); // => bar
await client.removeRemote(result.fragmentIdentifier);
```

To use a second factor:

```typescript
const client = new EtherealSecretsClient({
  endpoint: 'http://localhost:8080/secrets',
});
const result = await client.saveRemote('foo', 'bar', { secondFactor: 'baz' });
await client.getRemote(result.fragmentIdentifier, { secondFactor: 'baz' }); // => bar
await client.removeRemote(result.fragmentIdentifier, { secondFactor: 'baz' });
```

## Test suite

To run integration tests in this repository:

```sh
$ docker-compose -f docker-compose.test.yml up --abort-on-container-exit --build
```
