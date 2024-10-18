import * as chai from 'chai';
import * as cookieParser from 'cookie-parser';
import * as express from 'express';
import IORedis from 'ioredis';
import * as sinon from 'sinon';
import { Response } from 'superagent';
import { etherealSecrets } from '../index';
import { default as chaiHttp, request } from 'chai-http';
import chaiUuid = require('chai-uuid');
import UuidStatic = require('uuid');

let redis: IORedis;
let app: express.Express;
let clock: sinon.SinonFakeTimers;

before((done) => {
  redis = new IORedis({ host: 'redis' });
  chai.use(chaiHttp);
  chai.use(chaiUuid);
  done();
});

beforeEach((done) => {
  app = express();
  clock = sinon.useFakeTimers();
  done();
});

afterEach(() => {
  clock.restore();
});

function setupRemoteMiddleware(extraRemoteOptions?: Object) {
  let remoteOptions = Object.assign({ enabled: true }, extraRemoteOptions);
  app.use(
    '/secrets',
    etherealSecrets({
      remote: remoteOptions,
      redis: { host: 'redis' },
    }),
  );
}

describe('Ethereal Secrets Middleware', () => {
  it('should continue chain if no verb matches', async () => {
    app.use(
      '/secrets',
      etherealSecrets({
        remote: {
          enabled: true,
        },
        local: {
          ttl: 5,
        },
        redis: {
          host: 'redis',
        },
      }),
    );
    app.put('/secrets', (req, res) => {
      res.sendStatus(418);
    });
    try {
      const res = await request.agent(app).put('/secrets/');
      return chai.expect(res).to.have.status(418);
    } catch (err) {
      return chai.expect(err.response).to.have.status(418);
    }
  });

  it('should return new secret if no session exists', async () => {
    app.use(
      '/secrets',
      etherealSecrets({
        local: {
          ttl: 5,
        },
        redis: { host: 'redis' },
      }),
    );
    const res = await request
      .agent(app)
      .get('/secrets')
      .set('Accept', 'application/json');
    chai.expect(res).to.have.cookie('sessionid');
    chai.expect(res).to.have.status(200).and.be.json;
    chai.expect(res.body).to.be.an('object').with.key('key');
  });

  it('should return same secret on subsequent requests', async () => {
    app.use(
      '/secrets',
      etherealSecrets({
        local: {
          ttl: 5,
        },
        redis: { host: 'redis' },
      }),
    );
    let agent = request.agent(app);
    const firstRes = await agent
      .get('/secrets')
      .set('Accept', 'application/json');
    const secondRes = await agent
      .get('/secrets')
      .set('Accept', 'application/json');
    return chai.expect(firstRes.body.key).to.equal(secondRes.body.key);
  });

  it('should return different secret on subsequent requests when cookie changes', async () => {
    app.use(
      '/secrets',
      etherealSecrets({
        local: {
          ttl: 5,
        },
        redis: { host: 'redis' },
      }),
    );
    const firstRes = await request
      .agent(app)
      .get('/secrets')
      .set('Accept', 'application/json');
    const secondRes = await request
      .agent(app)
      .get('/secrets')
      .set('Accept', 'application/json');
    return chai.expect(firstRes.body.key).to.not.equal(secondRes.body.key);
  });

  it('should return different secret on subsequent requests after the ttl of cookie elapses', async () => {
    app.use(
      '/secrets',
      etherealSecrets({
        local: {
          ttl: 5,
        },
        redis: { host: 'redis' },
      }),
    );
    const res = await request
      .agent(app)
      .get('/secrets')
      .set('Accept', 'application/json');
    let time = new Date();
    time.setSeconds(time.getSeconds() + 5);
    let regex = new RegExp('sessionid=.+Expires=' + time.toUTCString() + ';');
    return chai.expect(res).to.have.header('set-cookie', regex);
  });

  it('should return different secret on subsequent requests after the ttl of redis entry elapses', async () => {
    app.use(
      '/secrets',
      etherealSecrets({
        local: {
          ttl: 9,
          cookie: {
            secret: 'supersecret',
          },
        },
        redis: { host: 'redis' },
      }),
    );
    const res = await request
      .agent(app)
      .get('/secrets')
      .set('Accept', 'application/json');
    let cookieValue = res
      .get('Set-Cookie')[0]
      .replace(/sessionid=(.+?);.+/, '$1');
    let unsignedCookie = cookieParser.signedCookie(
      decodeURIComponent(cookieValue),
      'supersecret',
    );
    let ttl = await redis.ttl('sess:' + unsignedCookie);
    return chai.expect(ttl).to.be.lessThan(10);
  });

  it('should store arbitrary data and return a uuid to it', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request.agent(app).post('/secrets').send({
      data: 'foo',
    });
    return Promise.all([
      chai.expect(res).to.have.status(201),
      chai.expect(res.body).to.be.an('object').with.keys('key', 'expiryDate'),
      (chai.expect(res.body['key']).to.be.a as any).uuid(),
    ]);
  });

  it('should store arbitrary as long as requested', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request.agent(app).post('/secrets').send({
      data: 'foo',
      ttl: 1337,
    });
    let timeInEliteFuture = new Date();
    timeInEliteFuture.setSeconds(timeInEliteFuture.getSeconds() + 1337);
    return await Promise.all([
      chai.expect(res).to.have.status(201),
      chai.expect(res.body).to.be.an('object').with.keys('key', 'expiryDate'),
      chai
        .expect(new Date(res.body['expiryDate']).getTime())
        .to.equal(timeInEliteFuture.getTime()),
    ]);
  });

  it('should return status code 400 if data is missing', async () => {
    setupRemoteMiddleware.call(this);
    try {
      const res = await request
        .agent(app)
        .post('/secrets')
        .set('Accept', 'application/json');
      return chai.expect(res).to.have.status(400);
    } catch (err) {
      return chai.expect(err.response).to.have.status(400);
    }
  });

  it('should return the same data given the result uuid', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request
      .agent(app)
      .post('/secrets')
      .send({
        data: 'foo',
      })
      .set('Accept', 'application/json');
    let key = res.body['key'];
    const res2 = await request.agent(app).get('/secrets/' + key);
    return await Promise.all([
      chai.expect(res2).to.have.status(200),
      chai.expect(res2.body).to.be.an('object').with.keys('data', 'expiryDate'),
      chai.expect(res2.body['data']).to.equal('foo'),
    ]);
  });

  it('should return status code 400 when trying to get data via an invalid uuid', async () => {
    setupRemoteMiddleware.call(this);
    try {
      const res = await request
        .agent(app)
        .get('/secrets/foobar')
        .set('Accept', 'application/json');
      return chai.expect(res).to.have.status(400);
    } catch (err) {
      return chai.expect(err.response).to.have.status(400);
    }
  });

  it('should return status code 400 when trying to delete data via an invalid uuid', async () => {
    setupRemoteMiddleware.call(this);
    try {
      const res = await request.agent(app).del('/secrets/foobar');
      return chai.expect(res).to.have.status(400);
    } catch (err) {
      return chai.expect(err.response).to.have.status(400);
    }
  });

  it('should return 404 for a uuid that does not exist', async () => {
    setupRemoteMiddleware.call(this);
    try {
      const res = await request
        .agent(app)
        .get('/secrets/' + UuidStatic.v4())
        .set('Accept', 'application/json');
      return chai.expect(res).to.have.status(404);
    } catch (err) {
      return chai.expect(err.response).to.have.status(404);
    }
  });

  it('should return 404 for a uuid that was deleted', async () => {
    setupRemoteMiddleware.call(this);
    try {
      const res = await request
        .agent(app)
        .post('/secrets')
        .send({
          data: 'foo',
        })
        .set('Accept', 'application/json');

      let key = res.body['key'];
      await request.agent(app).del('/secrets/' + key);

      const res2 = await request.agent(app).get('/secrets/' + key);

      chai.expect(res2).to.have.status(404);
    } catch (err) {
      chai.expect(err.response).to.have.status(404);
    }
  });

  it('should return 404 for a key/value pair that has expired via the default ttl', async () => {
    setupRemoteMiddleware.call(this, { defaultTtl: 9 });
    const res = await request
      .agent(app)
      .post('/secrets')
      .send({
        data: 'foo',
      })
      .set('Accept', 'application/json');
    let key = res.body['key'];
    let ttl = await redis.ttl('remote:' + key);
    await Promise.all([
      chai.expect(ttl).to.be.lessThan(10),
      chai.expect(ttl).to.be.greaterThan(-1),
    ]);
  });

  it('should return 404 for a key/value pair that has expired via the explicit ttl', async () => {
    setupRemoteMiddleware.call(this);
    const res: Response = await request
      .agent(app)
      .post('/secrets')
      .send({
        data: 'foo',
        ttl: 9,
      })
      .set('Accept', 'application/json');

    const key = res.body['key'];
    const ttl = await redis.ttl('remote:' + key);

    chai.expect(ttl).to.be.lessThan(10);
    chai.expect(ttl).to.be.greaterThan(-1);
  });

  it('should use default ttl in case of an invalid explicit ttl', async () => {
    setupRemoteMiddleware.call(this);
    const res = await request
      .agent(app)
      .post('/secrets')
      .send({
        data: 'foo',
        ttl: 'invalid',
      })
      .set('Accept', 'application/json');

    let key = res.body['key'];
    let ttl = await redis.ttl('remote:' + key);
    chai.expect(ttl).to.be.greaterThan(10);
  });

  it('should use default ttl in case of a too large explicit ttl', async () => {
    setupRemoteMiddleware.call(this, {
      defaultTtl: 1337,
      maxTtl: 2000,
    });
    const res = await request
      .agent(app)
      .post('/secrets')
      .send({
        data: 'foo',
        ttl: 2001,
      })
      .set('Accept', 'application/json');

    const key = res.body['key'];
    const ttl = await redis.ttl('remote:' + key);

    chai.expect(ttl).to.be.lessThan(2000);
    chai.expect(ttl).to.be.greaterThan(-1);
  });

  it('should return 400 in case of a too long data in body', async () => {
    setupRemoteMiddleware.call(this, { maxLength: 8 });

    try {
      const res = await request
        .agent(app)
        .post('/secrets')
        .send({
          data: 'way too long',
        })
        .set('Accept', 'application/json');

      chai.expect(res).to.have.status(400);
    } catch (err) {
      chai.expect(err.response).to.have.status(400);
    }
  });

  it('should use a custom IORedis client if supplied', async () => {
    app.use(
      '/secrets',
      etherealSecrets({
        local: {
          ttl: 9,
          cookie: {
            secret: 'supersecret',
          },
        },
        redis: { client: redis },
      }),
    );
    const res = await request
      .agent(app)
      .get('/secrets')
      .set('Accept', 'application/json');
    let cookieValue = res
      .get('Set-Cookie')[0]
      .replace(/sessionid=(.+?);.+/, '$1');
    let unsignedCookie = cookieParser.signedCookie(
      decodeURIComponent(cookieValue),
      'supersecret',
    );
    let ttl = await redis.ttl('sess:' + unsignedCookie);
    return chai.expect(ttl).to.be.lessThan(10);
  });

  it('should return the same data given the result uuid and second factor', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    const res = await request
      .agent(app)
      .get('/secrets/' + key + '?secondFactor=bar');
    return await Promise.all([
      chai.expect(res).to.have.status(200),
      chai.expect(res.body).to.be.an('object').with.keys('data', 'expiryDate'),
      chai.expect(res.body['data']).to.equal('foo'),
    ]);
  });

  it('should throw error 401 if a second factor was set but is missing upon retrival', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    try {
      const res = await request.agent(app).get('/secrets/' + key);
      chai.expect(res).to.have.status(401);
    } catch (err) {
      if (err.response) {
        chai.expect(err.response).to.have.status(401);
      } else {
        throw err;
      }
    }
  });

  it('should throw error 401 if a second factor was set but is set wrong upon retrival', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    try {
      const res = await request
        .agent(app)
        .get('/secrets/' + key + '?secondFactor=baz');
      chai.expect(res).to.have.status(401);
    } catch (err) {
      if (err.response) {
        chai.expect(err.response).to.have.status(401);
      } else {
        throw err;
      }
    }
  });

  it('should throw error 401 if a second factor was set but is missing upon deletion', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    try {
      const res = await request.agent(app).delete('/secrets/' + key);
      chai.expect(res).to.have.status(401);
    } catch (err) {
      if (err.response) {
        chai.expect(err.response).to.have.status(401);
      } else {
        throw err;
      }
    }
  });

  it('should throw error 401 if a second factor was set but is set wrong upon deletion', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    try {
      const res = await request
        .agent(app)
        .delete('/secrets/' + key + '?secondFactor=baz');
      chai.expect(res).to.have.status(401);
    } catch (err) {
      if (err.response) {
        chai.expect(err.response).to.have.status(401);
      } else {
        throw err;
      }
    }
  });

  it('should delete the second factor from redis as well when deleting the data', async () => {
    setupRemoteMiddleware.call(this);
    const key = await storeRemoteData({
      data: 'foo',
      secondFactor: 'bar',
    });
    const res = await request
      .agent(app)
      .delete('/secrets/' + key + '?secondFactor=bar');
    chai.expect(res).to.have.status(200);
    const exists = await redis.exists(`remote:${key}:secondFactor`);
    chai.expect(exists).to.equal(0);
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
    chai.expect(ttlData).to.equal(ttlSecondFactor);
  });
});

async function storeRemoteData(data: {
  data: string;
  ttl?: number;
  secondFactor?: string;
}) {
  const res = await request
    .agent(app)
    .post('/secrets')
    .send(data)
    .set('Accept', 'application/json');
  return res.body['key'];
}
