import * as crypto from 'crypto';

import { TextEncoder, TextDecoder } from 'util';

Object.defineProperty(global.self, 'crypto', {
  value: {
    subtle: crypto.webcrypto.subtle,
    getRandomValues: (arr: any) => crypto.randomBytes(arr.length),
  },
});
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
