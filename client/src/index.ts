import { agent, SuperAgent, SuperAgentRequest } from 'superagent';

export interface EtherealSecretsClientConfig {
  endpoint: string;
  storage?: Storage;
  cacheKey?: boolean;
}

export interface RemoteSaveResult {
  fragmentIdentifier: string;
  expiryDate?: Date;
}

export interface RemoteRetrieveResult {
  clearText: string;
  expiryDate?: Date;
}

export class EtherealSecretsClient {
  private _storage: Storage;
  private _endpoint: string;
  private _cacheKey: boolean;
  private _key: string;
  private _agent: SuperAgent<SuperAgentRequest>;

  constructor(config: EtherealSecretsClientConfig) {
    this._storage = config?.storage || window.sessionStorage;
    this._cacheKey = config?.cacheKey || false;
    this._endpoint = config.endpoint.endsWith('/')
      ? config.endpoint
      : config.endpoint + '/';
    this._agent = agent();
  }

  private fromBase64(data: string): Uint8Array {
    return new Uint8Array(
      window
        .atob(data)
        .split('')
        .map(function (c) {
          return c.charCodeAt(0);
        })
    );
  }

  private toBase64(data: Uint8Array): string {
    const chunkSize = 0x1000;
    const chunks = [];

    for (let i = 0; i < data.length; i += chunkSize) {
      chunks.push(
        String.fromCharCode.apply(null, data.subarray(i, i + chunkSize))
      );
    }

    return window.btoa(chunks.join(''));
  }

  private async decrypt(secret: string, cipherText: string): Promise<string> {
    const encryptedObj = JSON.parse(cipherText);
    const iv = this.fromBase64(encryptedObj.iv);
    const salt = this.fromBase64(encryptedObj.salt);
    const data = this.fromBase64(encryptedObj.encrypted);
    const additionalData = this.fromBase64(encryptedObj.additionalData);
    const key = await this.deriveKey(secret, salt);

    return new TextDecoder('utf8').decode(
      await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
          tagLength: 128,
          additionalData,
        },
        key,
        data
      )
    );
  }

  private async encrypt(secret: string, clearText: string): Promise<string> {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const additionalData = window.crypto.getRandomValues(new Uint8Array(16));
    const data = new TextEncoder().encode(clearText);
    const key = await this.deriveKey(secret, salt);
    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
        additionalData,
      },
      key,
      data
    );
    return JSON.stringify({
      encrypted: this.toBase64(new Uint8Array(encrypted)),
      salt: this.toBase64(salt),
      iv: this.toBase64(iv),
      additionalData: this.toBase64(additionalData),
    });
  }

  private async deriveKey(secret: string, salt: Uint8Array) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100_000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  public async getLocal(key: string): Promise<string | null> {
    const cipherText = this._storage.getItem(key);

    if (cipherText) {
      return this.decryptCipherText(cipherText);
    }

    return null;
  }

  public removeLocal(key: string) {
    this._storage.removeItem(key);
  }

  public async saveLocal(key: string, clearText: string): Promise<void> {
    const cipherText = await this.encryptClearText(clearText);

    if (cipherText !== null) {
      this._storage.setItem(key, cipherText);
    }
  }

  public async getRemote(
    fragmentIdentifier: string,
    options: { secondFactor?: string } = {}
  ): Promise<RemoteRetrieveResult> {
    try {
      const keys = this.parseFragmentIdentifier(fragmentIdentifier);
      const { secondFactor } = options;
      const res = await this._agent
        .get(
          this._endpoint +
            keys.remoteKey +
            (secondFactor ? `?secondFactor=${secondFactor}` : '')
        )
        .accept('application/json');

      if (!res.body.data) {
        throw new Error('The server did not answer with any data');
      }

      const clearText = await this.decrypt(keys.localKey, res.body.data);
      const result: RemoteRetrieveResult = {
        clearText: clearText,
      };

      if (res.body.expiryDate) {
        result.expiryDate = new Date(res.body.expiryDate);
      }

      return result;
    } catch (err) {
      throw new Error(err.message);
    }
  }

  public async removeRemote(
    fragmentIdentifier: string,
    options: { secondFactor?: string } = {}
  ): Promise<void> {
    const keys = this.parseFragmentIdentifier(fragmentIdentifier);
    const { secondFactor } = options;
    await this._agent
      .del(
        this._endpoint +
          keys.remoteKey +
          (secondFactor ? `?secondFactor=${secondFactor}` : '')
      )
      .accept('application/json');
  }

  public async saveRemote(
    clearText: string,
    options: { secondFactor?: string } = {}
  ): Promise<RemoteSaveResult> {
    try {
      const secret = this.generateLocalSecret();
      const cipherText = await this.encrypt(secret, clearText);
      const { secondFactor } = options;

      const res = await this._agent
        .post(this._endpoint)
        .send({ data: cipherText.toString(), secondFactor })
        .accept('application/json');

      if (!res.body.hasOwnProperty('key')) {
        throw new Error('The server did not answer with a key');
      }

      const result: RemoteSaveResult = {
        fragmentIdentifier: res.body.key + ';' + secret,
      };

      if (res.body.hasOwnProperty('expiryDate')) {
        result.expiryDate = new Date(res.body.expiryDate);
      }

      return result;
    } catch (err) {
      throw new Error(err.message);
    }
  }

  private parseFragmentIdentifier(fragmentIdentifier: string): {
    remoteKey: string;
    localKey: string;
  } {
    const regex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12};[0-9a-f]{64}$/;

    if (!regex.test(fragmentIdentifier)) {
      throw new Error('Fragment identifier is invalid');
    }

    const [remoteKey, localKey] = fragmentIdentifier.split(';');
    return { remoteKey, localKey };
  }

  private generateLocalSecret(): string {
    const randomValues = new Uint8Array(32);

    if (typeof crypto !== 'undefined') {
      crypto.getRandomValues(randomValues);
    } else if (typeof window !== 'undefined' && window['msCrypto']) {
      window['msCrypto'].getRandomValues(randomValues);
    } else {
      throw new Error('No secure source of randomness');
    }

    return randomValues.reduce(
      (prev, i) => prev + ((i < 16 ? '0' : '') + i.toString(16)),
      ''
    );
  }

  private async decryptCipherText(cipherText: string): Promise<string | null> {
    const secret = await this.retrieveRemoteSecret();
    return this.decrypt(secret, cipherText);
  }

  private async encryptClearText(value: string): Promise<string | null> {
    const secret = await this.retrieveRemoteSecret();
    return this.encrypt(secret, value);
  }

  private async retrieveRemoteSecret(): Promise<string> {
    if (this._key != null) {
      return this._key;
    }

    try {
      const res = await this._agent
        .get(this._endpoint)
        .withCredentials()
        .accept('application/json');

      if (!res.body.key) {
        throw new Error('The server did not answer with a key');
      }

      if (this._cacheKey) {
        this._key = res.body.key;
      }

      return res.body.key as string;
    } catch (err) {
      throw new Error(err.message);
    }
  }
}
