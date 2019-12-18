import { etherealSecrets } from '@neoskop/ethereal-secrets-middleware';
import * as express from 'express';
import * as helmet from 'helmet';

const app = express();
app.use(
  helmet({
    noCache: true,
  }),
);
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
  }),
);
app.listen(8080);
