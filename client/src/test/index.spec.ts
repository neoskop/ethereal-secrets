/**
 * @jest-environment jsdom
 * @jest-environment-options {"url": "http://server:8080"}
 */

import { EtherealSecretsClient, EtherealSecretsClientConfig } from '../index';

function createClient(config: Object = {}): EtherealSecretsClient {
  const defaultConfig: EtherealSecretsClientConfig = {
    endpoint: 'http://server:8080',
  };

  return new EtherealSecretsClient(Object.assign(defaultConfig, config));
}

describe('Ethereal Secrets Client', () => {
  it('should return null if item does not exist', () => {
    const sut: EtherealSecretsClient = createClient({
      storage: window.localStorage,
    });
    return expect(
      sut.getLocal('foo' + Math.random().toString(36).substring(7)),
    ).resolves.toBe(null);
  });

  it('should save to local storage if requested', async () => {
    const sut: EtherealSecretsClient = createClient({
      storage: window.localStorage,
    });
    await sut.saveLocal('foo', 'bar');
    return expect(window.localStorage.getItem('foo')).not.toBeNull();
  });

  it('should save to session storage per default', async () => {
    const sut: EtherealSecretsClient = createClient();
    await sut.saveLocal('foo', 'bar');
    return expect(window.sessionStorage.getItem('foo')).not.toBeNull();
  });

  it('should not save clear text in storage', async () => {
    const sut: EtherealSecretsClient = createClient();
    await sut.saveLocal('foo', 'bar');
    return expect(window.sessionStorage.getItem('foo')).not.toContain('bar');
  });

  it('should return saved item unchanged', async () => {
    const sut: EtherealSecretsClient = createClient();
    await sut.saveLocal('foo', 'bar');
    return expect(sut.getLocal('foo')).resolves.toEqual('bar');
  });

  it('should return saved item unchanged when key caching is enabled', async () => {
    const sut: EtherealSecretsClient = createClient({
      cacheKey: true,
    });
    await sut.saveLocal('foo', 'bar');
    return expect(sut.getLocal('foo')).resolves.toEqual('bar');
  });

  it('should allow saving arbitrary data remotely and return a key to it', async () => {
    const sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo');
    expect(result.fragmentIdentifier).not.toHaveLength(0);
    expect(result.fragmentIdentifier).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12};[0-9a-f]{64}$/,
    );
  });

  it('should return input data unchanged when using returned fragment identifier', async () => {
    const sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo');

    return expect(sut.getRemote(result.fragmentIdentifier)).resolves.toEqual(
      expect.objectContaining({ clearText: 'foo' }),
    );
  });

  it('should reject invalid fragment identifier', () => {
    const sut: EtherealSecretsClient = createClient();
    return expect(sut.getRemote('invalididentifier')).rejects.toThrow(
      'invalid',
    );
  });

  it('should reject unknown fragment identifier', () => {
    const sut: EtherealSecretsClient = createClient();
    return expect(
      sut.getRemote(
        'decafbad-dead-dead-dead-decafbadadad;decafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbad',
      ),
    ).rejects.toThrow(/404/);
  });

  it('should not return data when the data was deleted beforehand', async () => {
    const sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo');
    await sut.removeRemote(result.fragmentIdentifier);
    return expect(sut.getRemote(result.fragmentIdentifier)).rejects.toThrow(
      /404/,
    );
  });

  it('should allow storage of large inputs', () => {
    const sut: EtherealSecretsClient = createClient();
    const randomValues = window.crypto.getRandomValues(new Uint8Array(20_000));
    const bigInput = Array.from(randomValues, (dec) => {
      return dec.toString(16).padStart(2, '0');
    }).join('');
    return expect(sut.saveLocal('foo', bigInput)).resolves.not.toBeNull();
  });

  it('should allow storage and retrival with second factor', async () => {
    const sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo', { secondFactor: 'bar' });
    return expect(
      sut.getRemote(result.fragmentIdentifier, { secondFactor: 'bar' }),
    ).resolves.toEqual(
      expect.objectContaining({
        clearText: 'foo',
      }),
    );
  });

  it('should throw error when data stored with second factor is tried to be loaded without', async () => {
    const sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo', { secondFactor: 'bar' });
    return expect(sut.getRemote(result.fragmentIdentifier)).rejects.toThrow(
      /401/,
    );
  });

  it('should throw error when data stored with second factor is tried to be deleted without', async () => {
    const sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo', { secondFactor: 'bar' });
    return expect(sut.removeRemote(result.fragmentIdentifier)).rejects.toThrow(
      /401/,
    );
  });

  it('should throw error when data stored with second factor is tried to be deleted with the wrong second factor', async () => {
    const sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo', { secondFactor: 'baz' });
    return expect(sut.removeRemote(result.fragmentIdentifier)).rejects.toThrow(
      /401/,
    );
  });

  it('should allow deletion of data stored with second factor', async () => {
    const sut: EtherealSecretsClient = createClient();
    const result = await sut.saveRemote('foo', { secondFactor: 'bar' });
    return expect(
      sut.removeRemote(result.fragmentIdentifier, { secondFactor: 'bar' }),
    ).resolves;
  });
});
