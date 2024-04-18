import { etherealSecrets } from '@neoskop/ethereal-secrets-middleware';
import * as express from 'express';
import helmet from 'helmet';
import * as nocache from 'nocache';

const app = express();
app.use(helmet(), nocache());
app.use(helmet.referrerPolicy({ policy: 'no-referrer' }));
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
    },
  }),
);

const config = {
  remote: {
    enabled: true,
  },
  redis: {
    host: process.env.REDIS_HOST || 'redis',
  },
  local: {
    cookie: {
      secure:
        typeof process.env.SECURE_COOKIE === 'string'
          ? process.env.SECURE_COOKIE === 'true'
          : true,
    },
  },
};

app.use('/', etherealSecrets(config));
app.listen(8080);
