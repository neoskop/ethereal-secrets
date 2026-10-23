// Node provides fetch, crypto, atob and btoa; only Web Storage is missing
class MemoryStorage {
  private items = new Map<string, string>();
  get length() {
    return this.items.size;
  }
  key(index: number) {
    return [...this.items.keys()][index] ?? null;
  }
  getItem(key: string) {
    return this.items.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.items.set(key, String(value));
  }
  removeItem(key: string) {
    this.items.delete(key);
  }
  clear() {
    this.items.clear();
  }
}

// Browsers keep the session cookie for `credentials: 'include'`; Node's fetch
// does not. ponytail: single-origin jar, enough for one test server
let cookie = '';
const nodeFetch = globalThis.fetch;
async function fetchWithCookies(input: RequestInfo | URL, init?: RequestInit) {
  const headers = new Headers(init?.headers);
  if (cookie) headers.set('Cookie', cookie);
  const res = await nodeFetch(input, { ...init, headers });
  const setCookies = res.headers.getSetCookie();
  if (setCookies.length) {
    cookie = setCookies.map((c) => c.split(';')[0]).join('; ');
  }
  return res;
}

Object.assign(globalThis, {
  window: globalThis,
  localStorage: new MemoryStorage(),
  sessionStorage: new MemoryStorage(),
  fetch: fetchWithCookies,
});

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

beforeAll(async () => {
  const url = 'http://server:8080/health';
  let lastError: unknown;
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return;
    } catch (err) {
      lastError = err;
    }
    await wait(1000);
  }
  throw lastError ?? new Error('Server not reachable at ' + url);
}, 35000);
