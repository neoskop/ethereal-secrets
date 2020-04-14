import session = require('express-session');
import UuidStatic = require('uuid');
import * as bodyParser from 'body-parser';
import * as RedisStore from 'connect-redis';
import { RedisStoreOptions } from 'connect-redis';
import * as crypto from 'crypto';
import * as deepmerge from 'deepmerge';
import {
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from 'express-serve-static-core';
import * as ioredis from 'ioredis';
import * as Validator from 'validator';

export interface EtherealSecretsConfig {
  local?: {
    cookie?: {
      secret?: string;
      name?: string;
      secure?: boolean;
      path?: string;
      sameSite?: boolean | 'lax' | 'strict' | 'none';
    };
    ttl?: number;
  };
  remote?: {
    enabled?: boolean;
    defaultTtl?: number;
    maxTtl?: number;
    maxLength?: number;
  };
  trustProxy?: boolean;
  redis?: RedisStoreOptions;
}

const parseUuid = (
  req: Request,
  res: Response,
  uuidConsumer: (uuid?: string) => void,
) => {
  const requestUuid = req.path.replace(/^\/|\/$/g, '');

  if (Validator.default.isUUID(requestUuid)) {
    uuidConsumer(requestUuid);
  } else {
    res.sendStatus(400);
  }
};

const handleLocalEncryption = (
  sessionHandler: RequestHandler,
  req: Request,
  res: Response,
) => {
  sessionHandler(req, res, () => {
    if (!req.session.key) {
      req.session.key = crypto.randomBytes(32).toString('base64');
    }

    res.json({
      key: req.session.key,
    });
  });
};

const readRemotelyEncrypted = async (
  redisClient: ioredis.Redis,
  uuid: string,
  res: Response,
) => {
  const key = 'remote:' + uuid;
  const data = await redisClient.get(key);

  if (data == null) {
    res.sendStatus(404);
  } else {
    const ttl = await redisClient.ttl(key);

    if (ttl < 0) {
      res.sendStatus(500);
    } else {
      const expiryDate = new Date();
      expiryDate.setSeconds(expiryDate.getSeconds() + ttl);
      res.json({
        data: data,
        expiryDate: expiryDate.toUTCString(),
      });
    }
  }
};

const createRemotelyEncrypted = function (
  req: Request,
  res: Response,
  redisClient: ioredis.Redis,
  config: { defaultTtl?: number; maxTtl?: number; maxLength?: number },
) {
  bodyParser.json()(req, res, () => {
    if (
      !req.body.hasOwnProperty('data') ||
      req.body.data.length > config.maxLength
    ) {
      res.sendStatus(400);
    } else {
      const uuid = UuidStatic.v4();
      let ttl = config.defaultTtl;

      if (req.body.hasOwnProperty('ttl')) {
        const requestedTtl = parseInt(req.body.ttl);

        if (requestedTtl > 0 && requestedTtl <= config.maxTtl) {
          ttl = requestedTtl;
        }
      }

      const redisKey = 'remote:' + uuid;
      redisClient.set(redisKey, req.body.data, (err: Error) => {
        if (err) {
          throw err;
        }

        redisClient.expire(redisKey, ttl, (err: Error) => {
          if (err) {
            throw err;
          }

          var expiryDate = new Date();
          expiryDate.setSeconds(expiryDate.getSeconds() + ttl);

          res.status(201).send({
            key: uuid,
            expiryDate: expiryDate.toUTCString(),
          });
        });
      });
    }
  });
};

async function removeRemotelyEncrypted(
  redisClient: ioredis.Redis,
  uuid: string,
  res: Response,
) {
  await redisClient.del('remote:' + uuid);
  res.sendStatus(200);
}

export function etherealSecrets(
  config: EtherealSecretsConfig,
): (req: Request, res: Response, next: NextFunction) => void {
  const mergedConfig = deepmerge(
    {
      local: {
        ttl: 4 * 60 * 60, // Default to 4 hours
        cookie: {
          name: 'sessionid',
          secret: crypto.randomBytes(32).toString('hex'),
        },
      },
      remote: {
        enabled: false,
        defaultTtl: 2 * 24 * 60 * 60, // Default to 2 days
        maxTtl: 7 * 24 * 60 * 60, // Default to 1 week
        maxLength: 64 * 1000,
      },
    },
    {
      local: config.local || {},
      remote: config.remote || {},
      trustProxy: config.trustProxy,
    },
  );

  const redisConfig: RedisStoreOptions = Object.assign({}, config.redis, {
    ttl: mergedConfig.local.ttl,
  });

  const redisClient: ioredis.Redis =
    (redisConfig.client as ioredis.Redis) || new ioredis(redisConfig);

  const sessionConfig: session.SessionOptions = {
    store: new (RedisStore(session))({
      client: redisClient,
      ttl: mergedConfig.local.ttl,
    }),
    name: mergedConfig.local.cookie.name,
    secret: mergedConfig.local.cookie.secret,
    resave: false,
    saveUninitialized: false,
    cookie: Object.assign(
      {
        httpOnly: true,
        maxAge: mergedConfig.local.ttl * 1000,
        path: '/',
        secure: false,
        sameSite: 'strict',
      },
      mergedConfig.local.cookie,
    ),
  };

  const sessionHandler: RequestHandler = session(sessionConfig);
  return (req: Request, res: Response, next: NextFunction) => {
    if (mergedConfig.remote.enabled) {
      switch (req.method) {
        case 'GET':
          if (req.path === '/') {
            return handleLocalEncryption(sessionHandler, req, res);
          } else {
            return parseUuid(req, res, (uuid) =>
              readRemotelyEncrypted(redisClient, uuid, res),
            );
          }

        case 'POST':
          return createRemotelyEncrypted(
            req,
            res,
            redisClient,
            mergedConfig.remote,
          );

        case 'DELETE':
          return parseUuid(req, res, (uuid) =>
            removeRemotelyEncrypted(redisClient, uuid, res),
          );
      }
    } else {
      return handleLocalEncryption(sessionHandler, req, res);
    }

    next();
  };
}
