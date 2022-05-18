import { decrypt, encrypt } from 'sjcl';
import * as request from 'superagent';
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
    this._storage = config?.storage || sessionStorage;
    this._cacheKey = config?.cacheKey || false;
    this._endpoint = config.endpoint.endsWith('/')
      ? config.endpoint
      : config.endpoint + '/';

    if (typeof window !== 'undefined') {
      this._agent = request;
    } else {
      this._agent = agent();
    }
  }

  public getLocal(key: string): Promise<string | null> {
    const cipherText = this._storage.getItem(key);

    if (!!cipherText) {
      return this.decryptCipherText(cipherText);
    }

    return Promise.resolve(null);
  }

  public removeLocal(key: string) {
    this._storage.removeItem(key);
  }

  public saveLocal(key: string, clearText: string): Promise<void> {
    return this.encryptClearText(clearText).then((cipherText) => {
      if (cipherText !== null) {
        this._storage.setItem(key, cipherText);
      }
      return Promise.resolve();
    });
  }

  public getRemote(fragmentIdentifier: string): Promise<RemoteRetrieveResult> {
    try {
      const keys = this.parseFragmentIdentifier(fragmentIdentifier);
      return this._agent
        .get(this._endpoint + keys.remoteKey)
        .accept('application/json')
        .then((res) => {
          if (!res.body.data) {
            return Promise.reject('The server did not answer with any data');
          }

          try {
            const clearText = decrypt(keys.localKey, res.body.data);

            const result: RemoteRetrieveResult = {
              clearText: clearText,
            };

            if (res.body.expiryDate) {
              result.expiryDate = new Date(res.body.expiryDate);
            }

            return Promise.resolve(result);
          } catch (err) {
            return Promise.reject(err.message);
          }
        });
    } catch (err) {
      return Promise.reject(err.message);
    }
  }

  public removeRemote(fragmentIdentifier: string): Promise<void> {
    try {
      const keys = this.parseFragmentIdentifier(fragmentIdentifier);
      return this._agent
        .del(this._endpoint + keys.remoteKey)
        .accept('application/json')
        .then(() => {
          return Promise.resolve();
        });
    } catch (err) {
      return Promise.reject(err.message);
    }
  }

  public saveRemote(clearText: string): Promise<RemoteSaveResult> {
    const secret = this.generateLocalSecret();
    const cipherText = encrypt(secret, clearText);

    return this._agent
      .post(this._endpoint)
      .send({ data: cipherText.toString() })
      .accept('application/json')
      .then((res) => {
        if (!res.body.hasOwnProperty('key')) {
          return Promise.reject('The server did not answer with a key');
        }

        const result: RemoteSaveResult = {
          fragmentIdentifier: res.body.key + ';' + secret,
        };

        if (res.body.hasOwnProperty('expiryDate')) {
          result.expiryDate = new Date(res.body.expiryDate);
        }

        return Promise.resolve(result);
      })
      .catch((err) => {
        return Promise.reject(err.message);
      });
  }

  private parseFragmentIdentifier(fragmentIdentifier: string): {
    remoteKey: string;
    localKey: string;
  } {
    if (
      !fragmentIdentifier.match(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12};[0-9a-f]{64}$/
      )
    ) {
      throw new Error('Fragment identifier is invalid');
    }

    const fragmentParts = fragmentIdentifier.split(';');

    return {
      remoteKey: fragmentParts[0],
      localKey: fragmentParts[1],
    };
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

  private decryptCipherText(cipherText: string): Promise<string | null> {
    return this.retrieveRemoteSecret().then((secret) => {
      try {
        const clearText = decrypt(secret, cipherText);
        return Promise.resolve(clearText);
      } catch (err) {
        return Promise.reject(err.message);
      }
    });
  }

  private encryptClearText(value: string): Promise<string | null> {
    return this.retrieveRemoteSecret().then((secret) => {
      const cipherText = encrypt(secret, value);
      return Promise.resolve(cipherText.toString());
    });
  }

  private retrieveRemoteSecret(): Promise<string> {
    if (this._key != null) {
      return Promise.resolve(this._key);
    }

    return this._agent
      .get(this._endpoint)
      .withCredentials()
      .accept('application/json')
      .then((res) => {
        if (!res.body.key) {
          return Promise.reject('The server did not answer with a key');
        }

        if (this._cacheKey) {
          this._key = res.body.key;
        }

        return Promise.resolve(res.body.key as string);
      })
      .catch((err) => {
        return Promise.reject(err.message);
      });
  }
}
