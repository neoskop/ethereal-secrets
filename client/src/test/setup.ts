import { webcrypto } from 'crypto';
import { TextEncoder, TextDecoder } from 'util';
import axios from 'axios';

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
});

global.TextEncoder = TextEncoder as any;
global.TextDecoder = TextDecoder;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

beforeAll(async () => {
  const url = 'http://server:8080/health';
  let lastError: unknown;
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const res = await axios.get(url, { timeout: 1000 });
      if (res.status === 200) return;
    } catch (err) {
      lastError = err;
    }
    await wait(1000);
  }
  throw lastError ?? new Error('Server not reachable at ' + url);
}, 35000);
