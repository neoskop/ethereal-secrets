import * as crypto from 'crypto';
import * as express from 'express';
import { once } from 'events';
import { AddressInfo } from 'net';
import IORedis from 'ioredis';
import { etherealSecrets } from '../index';
jest.setTimeout(15000);

interface Response {
  status: number;
  body: any;
  cookies: string[];
}

// Serves the app on an ephemeral port for a single request, like supertest
async function request(
  method: string,
  path: string,
  { json, cookie }: { json?: unknown; cookie?: string } = {},
): Promise<Response> {
  const server = app.listen(0);
  await once(server, 'listening');
  try {
    const { port } = server.address() as AddressInfo;
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (json !== undefined) headers['Content-Type'] = 'application/json';
    if (cookie) headers['Cookie'] = cookie;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers,
      body: json === undefined ? undefined : JSON.stringify(json),
    });
    const text = await res.text();
    const isJson = res.headers.get('content-type')?.includes('json');
    return {
      status: res.status,
      body: isJson && text ? JSON.parse(text) : text,
      cookies: res.headers.getSetCookie(),
    };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

function withHttpConfig(config: any) {
  const base = {
    trustProxy: true,
    ...config,
    local: {
      ...config.local,
      cookie: { secure: false, ...config.local?.cookie },
    },
  };
  if (!base.redis) {
    base.redis = { client: redis };
  } else if (!base.redis.client) {
    base.redis.client = redis;
  }
  return base;
}

// Inverse of express-session's cookie signing: "s:<value>.<base64 hmac-sha256>"
function unsignCookie(cookie: string, secret: string): string {
  const signed = cookie.replace(/^s:/, '');
  const value = signed.slice(0, signed.lastIndexOf('.'));
  const mac = crypto
    .createHmac('sha256', secret)
    .update(value)
    .digest('base64')
    .replace(/=+$/, '');
  if (signed !== `${value}.${mac}`) {
    throw new Error('Invalid cookie signature');
  }
  return value;
}

let redis: IORedis;
let app: express.Express;

beforeAll(async () => {
  redis = new IORedis({ host: 'redis' });
});

afterAll(async () => {
  await redis.quit();
});

beforeEach((done) => {
  app = express();
  app.set('trust proxy', true);
  done();
});

afterEach(async () => {
  await redis.flushall();
});

function setupRemoteMiddleware(extraRemoteOptions?: Object) {
  let remoteOptions = Object.assign({ enabled: true }, extraRemoteOptions);
  app.use(
    '/secrets',
    etherealSecrets(
      withHttpConfig({
        remote: remoteOptions,
      }),
    ),
  );
}

describe('Ethereal Secrets Middleware', () => {
  it('should continue chain if no verb matches', async () => {
    app.use(
      '/secrets',
      etherealSecrets(
        withHttpConfig({
          remote: {
            enabled: true,
          },
          local: {
            ttl: 5,
          },
        }),
      ),
    );
    app.put('/secrets', (_req, res) => {
      res.sendStatus(418);
    });
    expect((await request('PUT', '/secrets/')).status).toBe(418);
  });

  it('should return new secret if no session exists', async () => {
    app.use(
      '/secrets',
      etherealSecrets(
        withHttpConfig({
          local: {
            ttl: 5,
          },
        }),
      ),
    );
    const res = await request('GET', '/secrets');
    expect(res.status).toBe(200);
    expect(res.cookies.some((cookie) => /sessionid=/.test(cookie))).toBe(true);
    expect(res.body).toHaveProperty('key');
  });

  it('should return same secret on subsequent requests', async () => {
    app.use(
      '/secrets',
      etherealSecrets(
        withHttpConfig({
          local: {
            ttl: 5,
          },
        }),
      ),
    );
    const firstRes = await request('GET', '/secrets');
    const secondRes = await request('GET', '/secrets', {
      cookie: firstRes.cookies[0].split(';')[0],
    });
    expect(firstRes.body.key).toEqual(secondRes.body.key);
  });

  it('should return different secret on subsequent requests when cookie changes', async () => {
    app.use(
      '/secrets',
      etherealSecrets(
        withHttpConfig({
          local: {
            ttl: 5,
          },
        }),
      ),
    );
    const firstRes = await request('GET', '/secrets');
    const secondRes = await request('GET', '/secrets');
    expect(firstRes.body.key).not.toEqual(secondRes.body.key);
  });

  it('should return different secret on subsequent requests after the ttl of cookie elapses', async () => {
    app.use(
      '/secrets',
      etherealSecrets(
        withHttpConfig({
          local: {
            ttl: 5,
          },
        }),
      ),
    );
    const res = await request('GET', '/secrets');
    let time = new Date();
    time.setSeconds(time.getSeconds() + 5);
    let regex = new RegExp('sessionid=.+Expires=' + time.toUTCString() + ';');
    expect(res.cookies.some((cookie) => regex.test(cookie))).toBe(true);
  });

  it('should return different secret on subsequent requests after the ttl of redis entry elapses', async () => {
    app.use(
      '/secrets',
      etherealSecrets(
        withHttpConfig({
          local: {
            ttl: 9,
            cookie: {
              secret: 'supersecret',
            },
          },
        }),
      ),
    );
    const res = await request('GET', '/secrets');
    const cookies = res.cookies;
    let cookieValue = cookies[0]?.replace(/sessionid=(.+?);.+/, '$1');
    let unsignedCookie = unsignCookie(
      decodeURIComponent(cookieValue),
      'supersecret',
    );
    let ttl = await redis.ttl('sess:' + unsignedCookie);
    expect(ttl).toBeLessThan(10);
  });

  it('should store arbitrary data and return a uuid to it', async () => {
    setupRemoteMiddleware();
    const res = await request('POST', '/secrets', {
      json: {
        data: 'foo',
      },
    });
    expect(res.status).toBe(201);
    expect(res.body).toEqual(
      expect.objectContaining({
        key: expect.any(String),
        expiryDate: expect.anything(),
      }),
    );
    expect(validateUuid(res.body['key'])).toBe(true);
  });

  it('should store arbitrary as long as requested', async () => {
    setupRemoteMiddleware();
    const res = await request('POST', '/secrets', {
      json: {
        data: 'foo',
        ttl: 1337,
      },
    });
    expect(res.status).toBe(201);
    let timeInEliteFuture = new Date();
    timeInEliteFuture.setSeconds(timeInEliteFuture.getSeconds() + 1337);
    expect(res.body).toEqual(
      expect.objectContaining({
        key: expect.any(String),
        expiryDate: expect.anything(),
      }),
    );
    const expiry = new Date(res.body['expiryDate']).getTime();
    expect(Math.abs(expiry - timeInEliteFuture.getTime())).toBeLessThanOrEqual(
      1000,
    );
  });

  it('should return status code 400 if data is missing', async () => {
    setupRemoteMiddleware();
    expect((await request('POST', '/secrets')).status).toBe(400);
  });

  it('should return the same data given the result uuid', async () => {
    setupRemoteMiddleware();
    const res = await request('POST', '/secrets', {
      json: {
        data: 'foo',
      },
    });
    expect(res.status).toBe(201);
    let key = res.body['key'];
    const res2 = await request('GET', '/secrets/' + key);
    expect(res2.status).toBe(200);
    expect(res2.body).toEqual(
      expect.objectContaining({
        data: 'foo',
        expiryDate: expect.anything(),
      }),
    );
  });

  it('should return status code 400 when trying to get data via an invalid uuid', async () => {
    setupRemoteMiddleware();
    expect((await request('GET', '/secrets/foobar')).status).toBe(400);
  });

  it('should return status code 400 when trying to delete data via an invalid uuid', async () => {
    setupRemoteMiddleware();
    expect((await request('DELETE', '/secrets/foobar')).status).toBe(400);
  });

  it('should return 404 for a uuid that does not exist', async () => {
    setupRemoteMiddleware();
    expect(
      (await request('GET', '/secrets/' + crypto.randomUUID())).status,
    ).toBe(404);
  });

  it('should return 404 for a uuid that was deleted', async () => {
    setupRemoteMiddleware();
    const res = await request('POST', '/secrets', {
      json: {
        data: 'foo',
      },
    });
    expect(res.status).toBe(201);

    let key = res.body['key'];
    expect((await request('DELETE', '/secrets/' + key)).status).toBe(200);

    expect((await request('GET', '/secrets/' + key)).status).toBe(404);
  });

  it('should return 404 for a key/value pair that has expired via the default ttl', async () => {
    setupRemoteMiddleware({ defaultTtl: 9 });
    const res = await request('POST', '/secrets', {
      json: {
        data: 'foo',
      },
    });
    expect(res.status).toBe(201);
    let key = res.body['key'];
    let ttl = await redis.ttl('remote:' + key);
    expect(ttl).toBeLessThan(10);
    expect(ttl).toBeGreaterThan(-1);
  });

  it('should return 404 for a key/value pair that has expired via the explicit ttl', async () => {
    setupRemoteMiddleware();
    const res = await request('POST', '/secrets', {
      json: {
        data: 'foo',
        ttl: 9,
      },
    });
    expect(res.status).toBe(201);

    const key = res.body['key'];
    const ttl = await redis.ttl('remote:' + key);

    expect(ttl).toBeLessThan(10);
    expect(ttl).toBeGreaterThan(-1);
  });

  it('should use default ttl in case of an invalid explicit ttl', async () => {
    setupRemoteMiddleware();
    const res = await request('POST', '/secrets', {
      json: {
        data: 'foo',
        ttl: 'invalid',
      },
    });
    expect(res.status).toBe(201);

    let key = res.body['key'];
    let ttl = await redis.ttl('remote:' + key);
    expect(ttl).toBeGreaterThan(10);
  });

  it('should use default ttl in case of a too large explicit ttl', async () => {
    setupRemoteMiddleware({
      defaultTtl: 1337,
      maxTtl: 2000,
    });
    const res = await request('POST', '/secrets', {
      json: {
        data: 'foo',
        ttl: 2001,
      },
    });
    expect(res.status).toBe(201);

    const key = res.body['key'];
    const ttl = await redis.ttl('remote:' + key);

    expect(ttl).toBeLessThan(2000);
    expect(ttl).toBeGreaterThan(-1);
  });

  it('should return 400 in case of a too long data in body', async () => {
    setupRemoteMiddleware({ maxLength: 8 });

    expect(
      (
        await request('POST', '/secrets', {
          json: {
            data: 'way too long',
          },
        })
      ).status,
    ).toBe(400);
  });

  it('should use a custom IORedis client if supplied', async () => {
    app.use(
      '/secrets',
      etherealSecrets(
        withHttpConfig({
          local: {
            ttl: 9,
            cookie: {
              secret: 'supersecret',
            },
          },
          redis: { client: redis },
        }),
      ),
    );
    const res = await request('GET', '/secrets');
    const cookies = res.cookies;
    let cookieValue = cookies[0]?.replace(/sessionid=(.+?);.+/, '$1');
    let unsignedCookie = unsignCookie(
      decodeURIComponent(cookieValue),
      'supersecret',
    );
    let ttl = await redis.ttl('sess:' + unsignedCookie);
    expect(ttl).toBeLessThan(10);
  });

  it('should return the same data given the result uuid and second factor', async () => {
    setupRemoteMiddleware();
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    const res = await request('GET', '/secrets/' + key + '?secondFactor=bar');
    expect(res.status).toBe(200);
    expect(res.body).toEqual(
      expect.objectContaining({
        data: 'foo',
        expiryDate: expect.anything(),
      }),
    );
  });

  it('should throw error 401 if a second factor was set but is missing upon retrival', async () => {
    setupRemoteMiddleware();
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    expect((await request('GET', '/secrets/' + key)).status).toBe(401);
  });

  it('should throw error 401 if a second factor was set but is set wrong upon retrival', async () => {
    setupRemoteMiddleware();
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    expect(
      (await request('GET', '/secrets/' + key + '?secondFactor=baz')).status,
    ).toBe(401);
  });

  it('should throw error 401 if a second factor was set but is missing upon deletion', async () => {
    setupRemoteMiddleware();
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    expect((await request('DELETE', '/secrets/' + key)).status).toBe(401);
  });

  it('should throw error 401 if a second factor was set but is set wrong upon deletion', async () => {
    setupRemoteMiddleware();
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    expect(
      (await request('DELETE', '/secrets/' + key + '?secondFactor=baz')).status,
    ).toBe(401);
  });

  it('should delete the second factor from redis as well when deleting the data', async () => {
    setupRemoteMiddleware();
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    expect(
      (await request('DELETE', '/secrets/' + key + '?secondFactor=bar')).status,
    ).toBe(200);
    const exists = await redis.exists(`remote:${key}:secondFactor`);
    expect(exists).toEqual(0);
  });

  it('should store the second factor with the same TTL', async () => {
    setupRemoteMiddleware();
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
      ttl: 500,
    });

    const ttlData = await redis.ttl(`remote:${key}`);
    const ttlSecondFactor = await redis.ttl(`remote:${key}:secondFactor`);
    expect(ttlData).toEqual(ttlSecondFactor);
  });
});

async function storeRemoteData(data: {
  data: string;
  ttl?: number;
  secondFactor?: string;
}) {
  const res = await request('POST', '/secrets', { json: data });
  expect(res.status).toBe(201);
  return res.body['key'];
}

function validateUuid(uuid: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    uuid,
  );
}
