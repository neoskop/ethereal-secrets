const express = require('express');
const { etherealSecrets } = require('@neoskop/ethereal-secrets-middleware');

const app = express();

app.get('/health', (_req, res) => res.sendStatus(200));

app.use(
  '/',
  etherealSecrets({
    trustProxy: true,
    local: {
      cookie: {
        secure: false,
      },
    },
    remote: {
      enabled: true,
    },
    redis: { host: 'redis' },
  }),
);

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Test server listening on ${port}`);
});
