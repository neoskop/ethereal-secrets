import * as cookieParser from 'cookie-parser';
import * as express from 'express';
import IORedis from 'ioredis';
import supertest = require('supertest');
import { validate as validateUuid, v4 as uuidV4 } from 'uuid';
import { etherealSecrets } from '../index';
type Response = supertest.Response;
const request = supertest;
jest.setTimeout(15000);

function withHttpConfig(config: any) {
  const base = {
    trustProxy: true,
    local: {
      cookie: { secure: false },
      ...(config.local || {}),
    },
    ...config,
  };
  if (!base.redis) {
    base.redis = { client: redis };
  } else if (!base.redis.client) {
    base.redis.client = redis;
  }
  return base;
}

function getCookies(res: Response): string[] {
  const raw = res.headers['set-cookie'];
  if (Array.isArray(raw)) {
    return raw;
  }
  if (typeof raw === 'string') {
    return [raw];
  }
  return [];
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
    await request(app).put('/secrets/').expect(418);
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
    const res = await request(app)
      .get('/secrets')
      .set('Accept', 'application/json')
      .expect(200);
    const cookies = getCookies(res);
    if (cookies.length) {
      expect(cookies.some((cookie) => /sessionid=/.test(cookie))).toBe(true);
    }
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
    let agent = request.agent(app);
    const firstRes = await agent.get('/secrets').set('Accept', 'application/json');
    const secondRes = await agent.get('/secrets').set('Accept', 'application/json');
    const cookies = getCookies(firstRes);
    if (cookies.length) {
      expect(firstRes.body.key).toEqual(secondRes.body.key);
    }
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
    const firstRes = await request(app)
      .get('/secrets')
      .set('Accept', 'application/json');
    const secondRes = await request(app)
      .get('/secrets')
      .set('Accept', 'application/json');
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
    const res = await request(app).get('/secrets').set('Accept', 'application/json');
    let time = new Date();
    time.setSeconds(time.getSeconds() + 5);
    let regex = new RegExp('sessionid=.+Expires=' + time.toUTCString() + ';');
    const cookies = getCookies(res);
    if (cookies.length) {
      expect(cookies.some((cookie) => regex.test(cookie))).toBe(true);
    }
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
    const res = await request(app).get('/secrets').set('Accept', 'application/json');
    const cookies = getCookies(res);
    let cookieValue = cookies[0]?.replace(/sessionid=(.+?);.+/, '$1');
    let unsignedCookie = cookieParser.signedCookie(
      decodeURIComponent(cookieValue),
      'supersecret',
    );
    let ttl = await redis.ttl('sess:' + unsignedCookie);
    expect(ttl).toBeLessThan(10);
  });

  it('should store arbitrary data and return a uuid to it', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request(app)
      .post('/secrets')
      .send({
        data: 'foo',
      })
      .expect(201);
    expect(res.body).toEqual(
      expect.objectContaining({
        key: expect.any(String),
        expiryDate: expect.anything(),
      }),
    );
    expect(validateUuid(res.body['key'])).toBe(true);
  });

  it('should store arbitrary as long as requested', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request(app)
      .post('/secrets')
      .send({
        data: 'foo',
        ttl: 1337,
      })
      .expect(201);
    let timeInEliteFuture = new Date();
    timeInEliteFuture.setSeconds(timeInEliteFuture.getSeconds() + 1337);
    expect(res.body).toEqual(
      expect.objectContaining({
        key: expect.any(String),
        expiryDate: expect.anything(),
      }),
    );
    const expiry = new Date(res.body['expiryDate']).getTime();
    expect(Math.abs(expiry - timeInEliteFuture.getTime())).toBeLessThanOrEqual(1000);
  });

  it('should return status code 400 if data is missing', async () => {
    setupRemoteMiddleware.call(this);
    await request(app)
      .post('/secrets')
      .set('Accept', 'application/json')
      .expect(400);
  });

  it('should return the same data given the result uuid', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request(app)
      .post('/secrets')
      .send({
        data: 'foo',
      })
      .set('Accept', 'application/json')
      .expect(201);
    let key = res.body['key'];
    const res2 = await request(app).get('/secrets/' + key).expect(200);
    expect(res2.body).toEqual(
      expect.objectContaining({
        data: 'foo',
        expiryDate: expect.anything(),
      }),
    );
  });

  it('should return status code 400 when trying to get data via an invalid uuid', async () => {
    setupRemoteMiddleware.call(this);
    await request(app)
      .get('/secrets/foobar')
      .set('Accept', 'application/json')
      .expect(400);
  });

  it('should return status code 400 when trying to delete data via an invalid uuid', async () => {
    setupRemoteMiddleware.call(this);
    await request(app).del('/secrets/foobar').expect(400);
  });

  it('should return 404 for a uuid that does not exist', async () => {
    setupRemoteMiddleware.call(this);
    await request(app)
      .get('/secrets/' + uuidV4())
      .set('Accept', 'application/json')
      .expect(404);
  });

  it('should return 404 for a uuid that was deleted', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request(app)
      .post('/secrets')
      .send({
        data: 'foo',
      })
      .set('Accept', 'application/json')
      .expect(201);

    let key = res.body['key'];
    await request(app).del('/secrets/' + key).expect(200);

    await request(app).get('/secrets/' + key).expect(404);
  });

  it('should return 404 for a key/value pair that has expired via the default ttl', async () => {
    setupRemoteMiddleware.call(this, { defaultTtl: 9 });
    const res = await request(app)
      .post('/secrets')
      .send({
        data: 'foo',
      })
      .set('Accept', 'application/json')
      .expect(201);
    let key = res.body['key'];
    let ttl = await redis.ttl('remote:' + key);
    expect(ttl).toBeLessThan(10);
    expect(ttl).toBeGreaterThan(-1);
  });

  it('should return 404 for a key/value pair that has expired via the explicit ttl', async () => {
    setupRemoteMiddleware.call(this);
    const res: Response = await request(app)
      .post('/secrets')
      .send({
        data: 'foo',
        ttl: 9,
      })
      .set('Accept', 'application/json')
      .expect(201);

    const key = res.body['key'];
    const ttl = await redis.ttl('remote:' + key);

    expect(ttl).toBeLessThan(10);
    expect(ttl).toBeGreaterThan(-1);
  });

  it('should use default ttl in case of an invalid explicit ttl', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request(app)
      .post('/secrets')
      .send({
        data: 'foo',
        ttl: 'invalid',
      })
      .set('Accept', 'application/json')
      .expect(201);

    let key = res.body['key'];
    let ttl = await redis.ttl('remote:' + key);
    expect(ttl).toBeGreaterThan(10);
  });

  it('should use default ttl in case of a too large explicit ttl', async () => {
    setupRemoteMiddleware.call(this, {
      defaultTtl: 1337,
      maxTtl: 2000,
    });
    const res = await request(app)
      .post('/secrets')
      .send({
        data: 'foo',
        ttl: 2001,
      })
      .set('Accept', 'application/json')
      .expect(201);

    const key = res.body['key'];
    const ttl = await redis.ttl('remote:' + key);

    expect(ttl).toBeLessThan(2000);
    expect(ttl).toBeGreaterThan(-1);
  });

  it('should return 400 in case of a too long data in body', async () => {
    setupRemoteMiddleware.call(this, { maxLength: 8 });

    await request(app)
      .post('/secrets')
      .send({
        data: 'way too long',
      })
      .set('Accept', 'application/json')
      .expect(400);
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
    const res = await request(app).get('/secrets').set('Accept', 'application/json');
    const cookies = getCookies(res);
    let cookieValue = cookies[0]?.replace(/sessionid=(.+?);.+/, '$1');
    let unsignedCookie = cookieParser.signedCookie(
      decodeURIComponent(cookieValue),
      'supersecret',
    );
    let ttl = await redis.ttl('sess:' + unsignedCookie);
    expect(ttl).toBeLessThan(10);
  });

  it('should return the same data given the result uuid and second factor', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    const res = await request(app)
      .get('/secrets/' + key + '?secondFactor=bar')
      .expect(200);
    expect(res.body).toEqual(
      expect.objectContaining({
        data: 'foo',
        expiryDate: expect.anything(),
      }),
    );
  });

  it('should throw error 401 if a second factor was set but is missing upon retrival', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    await request(app).get('/secrets/' + key).expect(401);
  });

  it('should throw error 401 if a second factor was set but is set wrong upon retrival', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    await request(app)
      .get('/secrets/' + key + '?secondFactor=baz')
      .expect(401);
  });

  it('should throw error 401 if a second factor was set but is missing upon deletion', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    await request(app).delete('/secrets/' + key).expect(401);
  });

  it('should throw error 401 if a second factor was set but is set wrong upon deletion', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    await request(app)
      .delete('/secrets/' + key + '?secondFactor=baz')
      .expect(401);
  });

  it('should delete the second factor from redis as well when deleting the data', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    await request(app)
      .delete('/secrets/' + key + '?secondFactor=bar')
      .expect(200);
    const exists = await redis.exists(`remote:${key}:secondFactor`);
    expect(exists).toEqual(0);
  });

  it('should store the second factor with the same TTL', async () => {
    setupRemoteMiddleware.call(this);
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
  const res = await request(app)
    .post('/secrets')
    .send(data)
    .set('Accept', 'application/json')
    .expect(201);
  return res.body['key'];
}
