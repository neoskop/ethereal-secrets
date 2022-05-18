import * as chai from 'chai';
import {
  EtherealSecretsClient,
  EtherealSecretsClientConfig,
  RemoteRetrieveResult,
  RemoteSaveResult,
} from '../index';
import * as chaiAsPromised from 'chai-as-promised';
import { Crypto } from '@peculiar/webcrypto';

before((done) => {
  chai.should();
  chai.use(chaiAsPromised);

  // let nodeLocalStorage = require('node-localstorage');
  // let LocalStorage = nodeLocalStorage.LocalStorage;

  // global['localStorage'] = new LocalStorage('./tmp/localstorage');
  // global['sessionStorage'] = new LocalStorage('./tmp/sessionstorage');
  global.crypto = new Crypto();
  done();
});

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
    let sut: EtherealSecretsClient = createClient({ storage: localStorage });
    return sut.getLocal('foo' + Math.random().toString(36).substring(7)).should
      .eventually.be.fulfilled.and.to.be.null;
  });

  it('should save to local storage if requested', () => {
    let sut: EtherealSecretsClient = createClient({ storage: localStorage });
    return sut
      .saveLocal('foo', 'bar')
      .should.eventually.be.fulfilled.and.then(() => {
        return chai.expect(localStorage.getItem('foo')).to.not.be.null;
      });
  });

  it('should save to session storage per default', () => {
    let sut: EtherealSecretsClient = createClient();
    return sut
      .saveLocal('foo', 'bar')
      .should.eventually.be.fulfilled.and.then(() => {
        return chai.expect(sessionStorage.getItem('foo')).to.not.be.null;
      });
  });

  it('should not save clear text in storage', () => {
    let sut: EtherealSecretsClient = createClient();
    return sut
      .saveLocal('foo', 'bar')
      .should.eventually.be.fulfilled.and.then(() => {
        return chai.expect(sessionStorage.getItem('foo')).to.not.contain('bar');
      });
  });

  it('should return saved item unchanged', () => {
    let sut: EtherealSecretsClient = createClient();
    return sut
      .saveLocal('foo', 'bar')
      .should.eventually.be.fulfilled.and.then(() => {
        return sut
          .getLocal('foo')
          .should.eventually.be.fulfilled.and.then((value) =>
            value.should.equal('bar')
          );
      });
  });

  it('should return saved item unchanged when key caching is enabled', () => {
    let sut: EtherealSecretsClient = createClient({
      cacheKey: true,
    });
    return sut
      .saveLocal('foo', 'bar')
      .should.eventually.be.fulfilled.and.then(() => {
        return sut
          .getLocal('foo')
          .should.eventually.be.fulfilled.and.then((value) =>
            value.should.equal('bar')
          );
      });
  });

  it('should allow saving arbitrary data remotely and return a key to it', () => {
    let sut: EtherealSecretsClient = createClient();
    return sut
      .saveRemote('foo')
      .should.eventually.be.fulfilled.and.then((result: RemoteSaveResult) => {
        return Promise.all([
          chai.expect(result.fragmentIdentifier).should.not.be.empty,
          chai
            .expect(result.fragmentIdentifier)
            .to.match(
              /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12};[0-9a-f]{64}$/
            ),
        ]);
      });
  });

  it('should return input data unchanged when using returned fragment identifier', () => {
    let sut: EtherealSecretsClient = createClient();
    return sut
      .saveRemote('foo')
      .should.eventually.be.fulfilled.and.then((result: RemoteSaveResult) => {
        return sut
          .getRemote(result.fragmentIdentifier)
          .should.eventually.be.fulfilled.and.then(
            (result: RemoteRetrieveResult) => {
              return result.clearText.should.equal('foo');
            }
          );
      });
  });

  it('should reject invalid fragment identifier', () => {
    let sut: EtherealSecretsClient = createClient();
    return sut
      .getRemote('invalididentifier')
      .should.eventually.be.rejectedWith('invalid');
  });

  it('should reject unknown fragment identifier', () => {
    let sut: EtherealSecretsClient = createClient();
    return sut
      .getRemote(
        'decafbad-dead-dead-dead-decafbadadad;decafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbad'
      )
      .should.eventually.be.rejectedWith('Not Found');
  });

  it('should not return data when the data was deleted beforehand', () => {
    let sut: EtherealSecretsClient = createClient();
    return sut
      .saveRemote('foo')
      .should.eventually.be.fulfilled.and.then((result: RemoteSaveResult) => {
        return sut.removeRemote(result.fragmentIdentifier).then(() => {
          return sut.getRemote(result.fragmentIdentifier).should.eventually.be
            .rejected;
        });
      });
  });
});
