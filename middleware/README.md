# Ethereal Secrets #

An express middleware to expose a REST endpoint to issue secrets for
client to encrypt their local stores with (the so called local mode) or
to store encrypted data for later retrieval (remote mode). The keys and
the cipher texts are stored in a Redis DB. Each entry in the database is
assigned a time-to-live thus making the secretes _ethereal_.

## Local mode ##

```typescript
let app = express();
app.use('/secrets', etherealSecrets({
  local: {
    ttl: 15 * 60,
    cookie: {
      secret: 'icanhazcheezburger?'
    }
  },
  redis: {
    host: 'localhost'
  }
}));
```

If a client now issues `GET /secrets` the API will return JSON in the
form of:

```json
{
  "key": "<the key>"
}
```

Along with a cookie containing a session ID. On subsequent requests the
same key is returned as long as the session is valid and the same cookie
is sent with the request.

## Remote mode ##

```typescript
let app = express();
app.use('/secrets', etherealSecrets({
  remote: {
    defaultTtl: 24 * 60 * 60
  },
  redis: {
    host: 'localhost'
  }
}));
```

If a client issues `POST /secrets` with arbitrary data as post body
parameter `data`, the API will return status code 201 and JSON in the
form of:

```json
{
  "key": "<the key>"
}
```

If a client now accesses `GET /secrets/<the key>` the API will return
JSON in the form of:

```json
{
  "data": "<the data>"
}
```