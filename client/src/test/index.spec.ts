/**
 * @jest-environment jsdom
 */

import {
  EtherealSecretsClient,
  EtherealSecretsClientConfig,
  RemoteRetrieveResult,
} from '../index';

function createClient(config: Object = {}): EtherealSecretsClient {
  let defaultConfig: EtherealSecretsClientConfig = {
    endpoint: 'http://server:8080',
  };

  Object.getOwnPropertyNames(config).forEach((key) => {
    if (config.hasOwnProperty(key)) {
      defaultConfig[key] = config[key];
    }
  });

  return new EtherealSecretsClient(defaultConfig);
}

describe('Ethereal Secrets Client', () => {
  it('should return null if item does not exist', () => {
    let sut: EtherealSecretsClient = createClient({
      storage: window.localStorage,
    });
    return expect(
      sut.getLocal('foo' + Math.random().toString(36).substring(7))
    ).resolves.toBe(null);
  });

  it('should save to local storage if requested', async () => {
    let sut: EtherealSecretsClient = createClient({
      storage: window.localStorage,
    });
    await sut.saveLocal('foo', 'bar');
    return expect(window.localStorage.getItem('foo')).not.toBeNull();
  });

  it('should save to session storage per default', async () => {
    let sut: EtherealSecretsClient = createClient();
    await sut.saveLocal('foo', 'bar');
    return expect(window.sessionStorage.getItem('foo')).not.toBeNull();
  });

  it('should not save clear text in storage', async () => {
    let sut: EtherealSecretsClient = createClient();
    await sut.saveLocal('foo', 'bar');
    return expect(window.sessionStorage.getItem('foo')).not.toContain('bar');
  });

  it('should return saved item unchanged', async () => {
    let sut: EtherealSecretsClient = createClient();
    await sut.saveLocal('foo', 'bar');
    return expect(sut.getLocal('foo')).resolves.toEqual('bar');
  });

  it('should return saved item unchanged when key caching is enabled', async () => {
    let sut: EtherealSecretsClient = createClient({
      cacheKey: true,
    });
    await sut.saveLocal('foo', 'bar');
    return expect(sut.getLocal('foo')).resolves.toEqual('bar');
  });

  it('should allow saving arbitrary data remotely and return a key to it', async () => {
    let sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo');
    expect(result.fragmentIdentifier).not.toHaveLength(0);
    expect(result.fragmentIdentifier).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12};[0-9a-f]{64}$/
    );
  });

  it('should return input data unchanged when using returned fragment identifier', async () => {
    let sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo');

    return expect(sut.getRemote(result.fragmentIdentifier)).resolves.toEqual(
      expect.objectContaining({ clearText: 'foo' })
    );
  });

  it('should reject invalid fragment identifier', () => {
    let sut: EtherealSecretsClient = createClient();
    return expect(sut.getRemote('invalididentifier')).rejects.toMatch(
      'invalid'
    );
  });

  it('should reject unknown fragment identifier', () => {
    let sut: EtherealSecretsClient = createClient();
    return expect(
      sut.getRemote(
        'decafbad-dead-dead-dead-decafbadadad;decafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbad'
      )
    ).rejects.toMatch('Not Found');
  });

  it('should not return data when the data was deleted beforehand', async () => {
    let sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo');
    await sut.removeRemote(result.fragmentIdentifier);
    return expect(sut.getRemote(result.fragmentIdentifier)).rejects.toMatch(
      'Not Found'
    );
  });

  it('should allow storage of large inputs', () => {
    let sut: EtherealSecretsClient = createClient();
    const randomValues = new Uint8Array(200_000);
    window.crypto.getRandomValues(randomValues);
    const bigInput = Array.from(randomValues, (dec) => {
      return dec.toString(16).padStart(2, '0');
    }).join('');
    return expect(sut.saveLocal('foo', bigInput)).resolves.not.toBeNull();
  });
});
