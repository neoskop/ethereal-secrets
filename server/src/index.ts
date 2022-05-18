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
app.use(
  '/',
  etherealSecrets({
    remote: {
      enabled: true,
    },
    redis: {
      host: process.env.REDIS_HOST || 'redis',
    },
  }),
);
app.listen(8080);
