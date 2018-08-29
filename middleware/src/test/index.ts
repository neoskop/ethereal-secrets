import * as chai from 'chai';
import * as express from 'express';
import {etherealSecrets} from "../index";
import * as sinon from "sinon";
import * as IORedis from "ioredis";
import * as cookieParser from "cookie-parser";
import chaiHttp = require('chai-http');
import chaiUuid = require('chai-uuid');
import UuidStatic = require("uuid");

before((done) => {
  this.redis = new IORedis({host: 'redis'});
  chai.use(chaiHttp);
  chai.use(chaiUuid);
  done();
});

beforeEach((done) => {
  this.app = express();
  this.clock = sinon.useFakeTimers();
  done();
});

afterEach(() => {
  this.clock.restore();
});

function setupRemoteMiddleware(extraRemoteOptions?: Object) {
  let remoteOptions = Object.assign({enabled: true}, extraRemoteOptions);
  this.app.use('/secrets', etherealSecrets({
    remote: remoteOptions
  }));
}

describe('Ethereal Secrets Middleware', () => {
  it('should continue chain if no verb matches', () => {
    this.app.use('/secrets', etherealSecrets({
      remote: {
        enabled: true
      },
      local: {
        ttl: 5
      }
    }));
    this.app.put('/secrets', (req, res) => {
      res.sendStatus(418);
    });
    return chai.request.agent(this.app)
    .put('/secrets/')
    .then(res => {
      return chai.expect(res).to.have.status(418);
    })
    .catch(err => {
      return chai.expect(err.response).to.have.status(418);
    });
  });

  it('should return new secret if no session exists', () => {
    this.app.use('/secrets', etherealSecrets({
      local: {
        ttl: 5
      }
    }));
    return chai.request(this.app)
    .get('/secrets')
    .set('Accept', 'application/json')
    .then(res => {
      chai.expect(res).to.have.cookie('sessionid');
      chai.expect(res).to.have.status(200).and.be.json;
      chai.expect(res.body).to.be.an('object').with.key('key');
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return same secret on subsequent requests', () => {
    this.app.use('/secrets', etherealSecrets({
      local: {
        ttl: 5
      }
    }));
    let agent = chai.request.agent(this.app);
    return agent
    .get('/secrets')
    .set('Accept', 'application/json')
    .then(firstRes => {
      return agent.get('/secrets').set('Accept', 'application/json').then(secondRes => {
        return chai.expect(firstRes.body.key).to.equal(secondRes.body.key);
      }).catch(err => {
        throw err;
      });
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return different secret on subsequent requests when cookie changes', () => {
    this.app.use('/secrets', etherealSecrets({
      local: {
        ttl: 5
      }
    }));
    return chai.request(this.app)
    .get('/secrets')
    .set('Accept', 'application/json')
    .then(firstRes => {
      return chai.request(this.app).get('/secrets').set('Accept', 'application/json').then(secondRes => {
        return chai.expect(firstRes.body.key).to.not.equal(secondRes.body.key);
      }).catch(err => {
        throw err;
      });
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return different secret on subsequent requests after the ttl of cookie elapses', () => {
    this.app.use('/secrets', etherealSecrets({
      local: {
        ttl: 5
      }
    }));
    return chai.request.agent(this.app)
    .get('/secrets')
    .set('Accept', 'application/json')
    .then(res => {
      let time = new Date();
      time.setSeconds(time.getSeconds() + 5);
      let regex = new RegExp('sessionid=.+Expires=' + time.toUTCString() + ';');
      return chai.expect(res).to.have.header('set-cookie', regex);
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return different secret on subsequent requests after the ttl of redis entry elapses', () => {
    this.app.use('/secrets', etherealSecrets({
      local: {
        ttl: 9,
        cookie: {
          secret: 'supersecret'
        }
      }
    }));
    return chai.request.agent(this.app)
    .get('/secrets')
    .set('Accept', 'application/json')
    .then(async (res: any) => {
      let cookieValue = res.res.headers['set-cookie'][0].replace(/sessionid=(.+?);.+/, "$1");
      let unsignedCookie = cookieParser.signedCookie(decodeURIComponent(cookieValue), 'supersecret');
      let ttl = await this.redis.ttl('sess:' + unsignedCookie);
      return chai.expect(ttl).to.be.lessThan(10);
    })
    .catch(err => {
      throw err;
    });
  });

  it('should store arbitrary data and return a uuid to it', () => {
    setupRemoteMiddleware.call(this);
    return chai.request(this.app)
    .post('/secrets')
    .send({
      data: 'foo'
    })
    .then(res => {
      return Promise.all([
        chai.expect(res).to.have.status(201),
        chai.expect(res.body).to.be.an('object').with.keys('key', 'expiryDate'),
        (chai.expect(res.body['key']).to.be.a as any).uuid()
      ]);
    })
    .catch(err => {
      throw err;
    });
  });

  it('should store arbitrary as long as requested', () => {
    setupRemoteMiddleware.call(this);
    return chai.request(this.app)
    .post('/secrets')
    .send({
      data: 'foo',
      ttl: 1337
    })
    .then(res => {
      let timeInEliteFuture = new Date();
      timeInEliteFuture.setSeconds(timeInEliteFuture.getSeconds() + 1337);
      return Promise.all([
        chai.expect(res).to.have.status(201),
        chai.expect(res.body).to.be.an('object').with.keys('key', 'expiryDate'),
        chai.expect(new Date(res.body['expiryDate']).getTime()).to.equal(timeInEliteFuture.getTime())
      ]);
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return status code 400 if data is missing', () => {
    setupRemoteMiddleware.call(this);
    return chai.request.agent(this.app)
    .post('/secrets')
    .set('Accept', 'application/json')
    .then(res => {
      return chai.expect(res).to.have.status(400);
    })
    .catch(err => {
      return chai.expect(err.response).to.have.status(400);
    });
  });

  it('should return the same data given the result uuid', () => {
    setupRemoteMiddleware.call(this);
    return chai.request.agent(this.app)
    .post('/secrets')
    .send({
      data: 'foo'
    })
    .set('Accept', 'application/json')
    .then(res => {
      let key = res.body['key'];
      return chai.request.agent(this.app).get('/secrets/' + key).then(res => {
        return Promise.all([
          chai.expect(res).to.have.status(200),
          chai.expect(res.body).to.be.an('object').with.keys('data', 'expiryDate'),
          chai.expect(res.body['data']).to.equal('foo')
        ]);
      }).catch(err => {
        throw err;
      });
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return status code 400 when trying to get data via an invalid uuid', () => {
    setupRemoteMiddleware.call(this);
    return chai.request.agent(this.app)
    .get('/secrets/foobar')
    .set('Accept', 'application/json')
    .then(res => {
      return chai.expect(res).to.have.status(400);
    })
    .catch(err => {
      return chai.expect(err.response).to.have.status(400);
    });
  });

  it('should return status code 400 when trying to delete data via an invalid uuid', () => {
    setupRemoteMiddleware.call(this);
    return chai.request.agent(this.app)
    .del('/secrets/foobar')
    .then(res => {
      return chai.expect(res).to.have.status(400);
    })
    .catch(err => {
      return chai.expect(err.response).to.have.status(400);
    });
  });

  it('should return 404 for a uuid that does not exist', () => {
    setupRemoteMiddleware.call(this);
    return chai.request.agent(this.app)
    .get('/secrets/' + UuidStatic.v4())
    .set('Accept', 'application/json')
    .then(res => {
      return chai.expect(res).to.have.status(404);
    })
    .catch(err => {
      return chai.expect(err.response).to.have.status(404);
    });
  });

  it('should return 404 for a uuid that was deleted', async () => {
    setupRemoteMiddleware.call(this);
    return chai.request.agent(this.app)
    .post('/secrets')
    .send({
      data: 'foo'
    })
    .set('Accept', 'application/json')
    .then(async res => {
      let key = res.body['key'];
      await chai.request.agent(this.app).del('/secrets/' + key);
      return chai.request.agent(this.app).get('/secrets/' + key).then(res => {
        return chai.expect(res).to.have.status(404);
      })
      .catch(err => {
        return chai.expect(err.response).to.have.status(404);
      });
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return 404 for a key/value pair that has expired via the default ttl', async () => {
    setupRemoteMiddleware.call(this, {defaultTtl: 9});
    return chai.request.agent(this.app)
    .post('/secrets')
    .send({
      data: 'foo'
    })
    .set('Accept', 'application/json')
    .then(async (res: any) => {
      let key = res.body['key'];
      let ttl = await this.redis.ttl('remote:' + key);
      return Promise.all([
        chai.expect(ttl).to.be.lessThan(10),
        chai.expect(ttl).to.be.greaterThan(-1)
      ]);
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return 404 for a key/value pair that has expired via the explicit ttl', async () => {
    setupRemoteMiddleware.call(this);
    return chai.request.agent(this.app)
    .post('/secrets')
    .send({
      data: 'foo',
      ttl: 9
    })
    .set('Accept', 'application/json')
    .then(async (res: any) => {
      let key = res.body['key'];
      let ttl = await this.redis.ttl('remote:' + key);
      return Promise.all([
        chai.expect(ttl).to.be.lessThan(10),
        chai.expect(ttl).to.be.greaterThan(-1)
      ]);
    })
    .catch(err => {
      throw err;
    });
  });

  it('should use default ttl in case of an invalid explicit ttl', async () => {
    setupRemoteMiddleware.call(this);
    return chai.request.agent(this.app)
    .post('/secrets')
    .send({
      data: 'foo',
      ttl: 'invalid'
    })
    .set('Accept', 'application/json')
    .then(async (res: any) => {
      let key = res.body['key'];
      let ttl = await this.redis.ttl('remote:' + key);
      return chai.expect(ttl).to.be.greaterThan(10);
    })
    .catch(err => {
      throw err;
    });
  });

  it('should use default ttl in case of a too large explicit ttl', async () => {
    setupRemoteMiddleware.call(this, {
      defaultTtl: 1337,
      maxTtl: 2000
    });
    return chai.request.agent(this.app)
    .post('/secrets')
    .send({
      data: 'foo',
      ttl: 2001
    })
    .set('Accept', 'application/json')
    .then(async (res: any) => {
      let key = res.body['key'];
      let ttl = await this.redis.ttl('remote:' + key);
      return Promise.all([
        chai.expect(ttl).to.be.lessThan(2000),
        chai.expect(ttl).to.be.greaterThan(-1)
      ]);
    })
    .catch(err => {
      throw err;
    });
  });

  it('should return 400 in case of a too long data in body', async () => {
    setupRemoteMiddleware.call(this, {maxLength: 8});
    return chai.request.agent(this.app)
    .post('/secrets')
    .send({
      data: 'way too long'
    })
    .set('Accept', 'application/json')
    .then(res => {
      return chai.expect(res).to.have.status(400);
    })
    .catch(err => {
      return chai.expect(err.response).to.have.status(400);
    });
  });
});
