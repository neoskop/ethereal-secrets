import { webcrypto } from 'crypto';

import { TextEncoder, TextDecoder } from 'util';

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
});

global.TextEncoder = TextEncoder as any;
global.TextDecoder = TextDecoder;
