import { Crypto } from '@peculiar/webcrypto';
import { TextEncoder, TextDecoder } from 'util';

global.crypto = new Crypto();
window.crypto = global.crypto;
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
