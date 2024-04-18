import * as session from 'express-session';
import UuidStatic = require('uuid');
import * as bodyParser from 'body-parser';
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
import { RedisOptions } from 'ioredis';
import RedisStore from 'connect-redis';

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
  redis?: { client?: any } & RedisOptions;
}

const parseUuid = (
  req: Request,
  res: Response,
  uuidConsumer: (uuid?: string) => void,
) => {
  const requestUuid = req.path.replace(/(^\/|\/$)/g, '');

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
    if (!(req.session as any).key) {
      (req.session as any).key = crypto.randomBytes(32).toString('base64');
    }

    res.json({
      key: (req.session as any).key,
    });
  });
};

const readRemotelyEncrypted = async (
  redisClient: ioredis.Redis,
  uuid: string,
  req: Request,
  res: Response,
) => {
  const key = 'remote:' + uuid;
  const data = await redisClient.get(key);

  if (data == null) {
    res.sendStatus(404);
  } else {
    try {
      await handleSecondFactor(uuid, redisClient, req);
    } catch (err) {
      res.sendStatus(401);
      return;
    }

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

const createRemotelyEncrypted = async (
  req: Request,
  res: Response,
  redisClient: ioredis.Redis,
  config: { defaultTtl?: number; maxTtl?: number; maxLength?: number },
) => {
  const { data, ttl, secondFactor } = req.body;
  const { maxLength, defaultTtl, maxTtl } = config;

  if (!data || data.length > maxLength) {
    res.sendStatus(400);
    return;
  }

  const uuid = UuidStatic.v4();
  let expiryDate = new Date();
  let redisKey = `remote:${uuid}`;

  let expiration = defaultTtl;
  if (ttl && ttl <= maxTtl) {
    expiration = ttl;
  }

  if (secondFactor) {
    await storeSecondFactor(uuid, secondFactor, expiration, redisClient);
  }

  try {
    await redisClient.set(redisKey, data);
    await redisClient.expire(redisKey, expiration);

    expiryDate.setSeconds(expiryDate.getSeconds() + expiration);

    res.status(201).send({
      key: uuid,
      expiryDate: expiryDate.toUTCString(),
    });
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
};

async function handleSecondFactor(
  uuid: string,
  redisClient: ioredis.Redis,
  req: Request,
) {
  if (await hasSecondFactor(uuid, redisClient)) {
    const storedSecondFactor = await getSecondFactor(uuid, redisClient);
    const secondFactor = req.query.secondFactor;
    if (Array.isArray(secondFactor) || secondFactor !== storedSecondFactor) {
      throw new Error('Invalid second factor');
    }
  }
}

async function hasSecondFactor(
  uuid: string,
  redisClient: ioredis.Redis,
): Promise<boolean> {
  const redisKey = `remote:${uuid}:secondFactor`;
  return (await redisClient.exists(redisKey)) > 0;
}

async function storeSecondFactor(
  uuid: string,
  secondFactor: any,
  expiration: number,
  redisClient: ioredis.Redis,
) {
  const redisKey = `remote:${uuid}:secondFactor`;
  await redisClient.set(redisKey, secondFactor);
  await redisClient.expire(redisKey, expiration);
}

async function getSecondFactor(uuid: string, redisClient: ioredis.Redis) {
  const redisKey = `remote:${uuid}:secondFactor`;
  return await redisClient.get(redisKey);
}

async function removeRemotelyEncrypted(
  redisClient: ioredis.Redis,
  uuid: string,
  req: Request,
  res: Response,
) {
  try {
    await handleSecondFactor(uuid, redisClient, req);
  } catch (err) {
    res.sendStatus(401);
    return;
  }
  await redisClient.del(`remote:${uuid}:secondFactor`);
  await redisClient.del('remote:' + uuid);
  res.sendStatus(200);
}

export function etherealSecrets(
  config: EtherealSecretsConfig,
): RequestHandler[] {
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

  const redisClient: ioredis.Redis =
    (config.redis.client as ioredis.Redis) || new ioredis.default(config.redis);

  const sessionConfig: session.SessionOptions = {
    store: new RedisStore({
      client: redisClient,
      ttl: mergedConfig.local.ttl,
    }),
    name: mergedConfig.local.cookie.name,
    secret: mergedConfig.local.cookie.secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: mergedConfig.local.ttl * 1000,
      path: '/',
      secure:
        typeof mergedConfig.local.cookie.secure !== 'undefined'
          ? mergedConfig.local.cookie.secure
          : true,
      sameSite: 'strict',
      ...mergedConfig.local.cookie,
    },
  };

  const sessionHandler: RequestHandler = session(sessionConfig);
  return [
    bodyParser.json(),
    (req: Request, res: Response, next: NextFunction) => {
      if (mergedConfig.remote.enabled) {
        switch (req.method) {
          case 'GET':
            if (req.path === '/') {
              return handleLocalEncryption(sessionHandler, req, res);
            } else {
              return parseUuid(req, res, (uuid) =>
                readRemotelyEncrypted(redisClient, uuid, req, res),
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
              removeRemotelyEncrypted(redisClient, uuid, req, res),
            );
        }
      } else {
        return handleLocalEncryption(sessionHandler, req, res);
      }

      next();
    },
  ];
}
