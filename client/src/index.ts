import axios from 'axios';

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

  constructor(config: EtherealSecretsClientConfig) {
    this._storage = config?.storage || window.sessionStorage;
    this._cacheKey = config?.cacheKey || false;
    this._endpoint = config.endpoint.endsWith('/')
      ? config.endpoint
      : config.endpoint + '/';
  }

  private toBase64(data: Uint8Array): string {
    return Buffer.from(data).toString('base64');
  }

  private async decrypt(secret: string, cipherText: string): Promise<string> {
    const encryptedObj = JSON.parse(cipherText);
    const iv = Buffer.from(encryptedObj.iv, 'base64');
    const salt = Buffer.from(encryptedObj.salt, 'base64');
    const data = Buffer.from(encryptedObj.encrypted, 'base64');
    const additionalData = Buffer.from(encryptedObj.additionalData, 'base64');
    const key = await this.deriveKey(secret, salt);

    const clearText = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
        additionalData,
      },
      key,
      data,
    );
    return new TextDecoder('utf8').decode(clearText);
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
      data,
    );
    return JSON.stringify({
      encrypted: Buffer.from(new Uint8Array(encrypted)).toString('base64'),
      salt: Buffer.from(salt).toString('base64'),
      iv: Buffer.from(iv).toString('base64'),
      additionalData: Buffer.from(additionalData).toString('base64'),
    });
  }

  private async deriveKey(secret: string, salt: Uint8Array) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey'],
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
      ['encrypt', 'decrypt'],
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
    options: { secondFactor?: string } = {},
  ): Promise<RemoteRetrieveResult> {
    const keys = this.parseFragmentIdentifier(fragmentIdentifier);
    const { secondFactor } = options;
    const res = await axios.get(
      this._endpoint +
        keys.remoteKey +
        (secondFactor ? `?secondFactor=${secondFactor}` : ''),
      {
        headers: {
          'Content-Type': 'application/json',
        },
      },
    );

    if (!res.data.data) {
      throw new Error('The server did not answer with any data');
    }

    const clearText = await this.decrypt(keys.localKey, res.data.data);
    const result: RemoteRetrieveResult = {
      clearText: clearText,
    };

    if (res.data.expiryDate) {
      result.expiryDate = new Date(res.data.expiryDate);
    }

    return result;
  }

  public async removeRemote(
    fragmentIdentifier: string,
    options: { secondFactor?: string } = {},
  ): Promise<void> {
    const keys = this.parseFragmentIdentifier(fragmentIdentifier);
    const { secondFactor } = options;
    await axios.delete(
      this._endpoint +
        keys.remoteKey +
        (secondFactor ? `?secondFactor=${secondFactor}` : ''),
      {
        headers: {
          'Content-Type': 'application/json',
        },
      },
    );
  }

  public async saveRemote(
    clearText: string,
    options: { secondFactor?: string } = {},
  ): Promise<RemoteSaveResult> {
    try {
      const secret = this.generateLocalSecret();
      const cipherText = await this.encrypt(secret, clearText);
      const { secondFactor } = options;

      const res = await axios.post(
        this._endpoint,
        { data: cipherText.toString(), secondFactor },
        {
          headers: {
            'Content-Type': 'application/json',
          },
        },
      );

      if (!res.data.hasOwnProperty('key')) {
        throw new Error('The server did not answer with a key');
      }

      const result: RemoteSaveResult = {
        fragmentIdentifier: res.data.key + ';' + secret,
      };

      if (res.data.hasOwnProperty('expiryDate')) {
        result.expiryDate = new Date(res.data.expiryDate);
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
      '',
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

    const res = await axios.get(this._endpoint, {
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true,
    });

    if (!res.data.key) {
      throw new Error('The server did not answer with a key');
    }

    if (this._cacheKey) {
      this._key = res.data.key;
    }

    return res.data.key as string;
  }
}
