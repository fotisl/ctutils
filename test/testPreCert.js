/**
 * Certificate Transparency Utilities
 * Test PreCert
 *
 * By Fotis Loukos <me@fotisl.com>
 */

require('babel-polyfill');
const assert = require('assert');
const fs = require('fs');
const pvutils = require('pvutils');
const CTUtils = require('..');
const WebCrypto = require('node-webcrypto-ossl');

const webcrypto = new WebCrypto();
CTUtils.setWebCrypto(webcrypto);

const issuerHash = new Uint8Array(pvutils.stringToArrayBuffer(
  pvutils.fromBase64('q9kHBA4OE40+HVkOIjyKiKBED3yDP/uskMLt3i9Z7e8=')));
const preCertBuffer = fs.readFileSync('test/precert.bin');
const preCertBin = new Uint8Array(preCertBuffer);
const tbsBuffer = fs.readFileSync('test/tbs.bin');
const tbsBin = new Uint8Array(tbsBuffer);

describe('PreCert', () => {
  describe('#toBinary()', () => {
    it('should encode correctly', () => {
      const preCert = new CTUtils.PreCert(issuerHash.buffer, tbsBin.buffer);

      const preCertVerify = new Uint8Array(preCert.toBinary());

      assert.equal(preCertVerify.length, preCertBin.length,
        'Incorrect encoded length');

      for(let i = 0; i < preCertBin.length; i++)
        assert.equal(preCertVerify[i], preCertBin[i], `Failed at offset ${i}`);
    });
  });

  describe('#fromBinary()', () => {
    it('should decode correctly', () => {
      const preCert = CTUtils.PreCert.fromBinary(preCertBin.buffer);
      const issuerHashView = new Uint8Array(issuerHash);
      const issuerHashVerify = new Uint8Array(preCert.issuerHash);
      const tbsVerify = new Uint8Array(preCert.tbs);

      assert.equal(issuerHashView.length, issuerHashVerify.length,
        'Incorrect issuer hash length');

      for(let i = 0; i < issuerHashView.length; i++)
        assert.equal(issuerHashView[i], issuerHashVerify[i],
          `Failed issuer hash at offset ${i}`);

      assert.equal(tbsVerify.length, tbsBin.length, 'Incorrect tbs length');

      for(let i = 0; i < tbsBin.length; i++)
        assert.equal(tbsVerify[i], tbsBin[i], `Failed tbs at offset ${i}`);
    });
  });
});
