/**
 * Certificate Transparency Utilities
 * Webcrypto polyfill loader.
 *
 * By Fotis Loukos <me@fotisl.com>
 */
import * as pkijs from 'pkijs';
import WebCrypto from 'node-webcrypto-ossl';

/* Use openssl webcrypto polyfill for node */
const webcrypto = new WebCrypto();
pkijs.setEngine('OpenSSL', webcrypto, new pkijs.CryptoEngine({
  name: 'OpenSSL',
  crypto: webcrypto,
  subtle: webcrypto.subtle
}));
