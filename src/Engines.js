/**
 * Certificate Transparency Utilities
 * Polyfill loaders
 *
 * By Fotis Loukos <me@fotisl.com>
 */

import * as pkijs from 'pkijs';

const engines = {
  fetch: null,
  webcrypto: null
};

export function setFetch(fetch) {
  engines.fetch = fetch;
}

export function getFetch() {
  return engines.fetch;
}

export function setWebCrypto(webcrypto) {
  engines.webcrypto = webcrypto
  pkijs.setEngine('webcrypto', webcrypto, new pkijs.CryptoEngine({
    name: 'webcrypto',
    crypto: webcrypto,
    subtle: webcrypto.subtle
  }));
}

export function getWebCrypto() {
  return engines.webcrypto;
}

(function initEngines() {
  if(typeof self !== 'undefined') {
    if('fetch' in self) {
      engines.fetch = self.fetch;
    }

    engines.webcrypto = pkijs.getEngine().crypto;
  }
})();
