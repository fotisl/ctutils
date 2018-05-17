/**
 * Certificate Transparency Utilities
 * Test SignedCertificateTimestamp
 *
 * By Fotis Loukos <me@fotisl.com>
 */

require('babel-polyfill');
const assert = require('assert');
const fs = require('fs');
const pvutils = require('pvutils');
const CTUtils = require('..');

const logId = pvutils.stringToArrayBuffer(pvutils.fromBase64(
  'pFASaQVaFVReYhGrN7wQP2KuVXakXksXFEU+GyIQaiU='));

const pubKey = pvutils.stringToArrayBuffer(pvutils.fromBase64(
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp37MtRxT' +
  'mACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA=='));

const sctBin = new Uint8Array(pvutils.stringToArrayBuffer(pvutils.fromBase64(
  'AKRQEmkFWhVUXmIRqze8ED9irlV2pF5LFxRFPhsiEGolAAABYXV31yUAAAQDAEcwRQIgIFztN' +
  'JNfxaRdUWEwPRWwD5S2GfvijTgvPbVC2wBHOLkCIQCYr3u/5yXhKCOkj4Jm79DK3YouXxzpOg' +
  'S45xjWB6SJOg==')));

const sig = pvutils.stringToArrayBuffer(pvutils.fromBase64(
  'BAMARzBFAiAgXO00k1/FpF1RYTA9FbAPlLYZ++KNOC89tULbAEc4uQIhAJive7/nJeEoI6SPg' +
  'mbv0Mrdii5fHOk6BLjnGNYHpIk6'));

const certBuffer = fs.readFileSync('test/cert.der');
const cert = new Uint8Array(certBuffer.length);

for(let i = 0; i < certBuffer.length; i++)
  cert[i] = certBuffer[i];

describe('SignedCertificateTimestamp', () => {
  describe('#toBinary()', () => {
    it('should encode correctly', () => {
      const sct = new CTUtils.SignedCertificateTimestamp(CTUtils.Version.v1,
        logId, 1518094243621, new ArrayBuffer(0), sig, false, cert);

      const sctVerify = new Uint8Array(sct.toBinary());

      assert.equal(sctVerify.length, sctBin.length, 'Incorrect encoded length');

      for(let i = 0; i < sctBin.length; i++)
        assert.equal(sctVerify[i], sctBin[i], `Failed at offset ${i}`);
    });
  });

  describe('#fromBinary()', () => {
    it('should decode correctly', () => {
      const sct = CTUtils.SignedCertificateTimestamp.fromBinary(sctBin.buffer);

      assert.equal(sct.version, CTUtils.Version.v1, 'Incorrect version');

      const logIdVerifyView = new Uint8Array(sct.logId);
      const logIdView = new Uint8Array(logId);

      assert.equal(logIdVerifyView.length, logIdView.length,
        'Incorrect logId length');
      for(let i = 0; i < logIdVerifyView.length; i++)
        assert.equal(logIdVerifyView[i], logIdView[i],
          `Failed logId at offset ${i}`);

      assert.equal(sct.timestamp, 1518094243621, 'Incorrect timestamp');

      const extensionsVerifyView = new Uint8Array(sct.extensions);
      const extensionsView = new Uint8Array([]);

      assert.equal(extensionsVerifyView.length, extensionsView.length,
        'Incorrect extensions length');
      for(let i = 0; i < extensionsVerifyView.length; i++)
        assert.equal(extensionsVerifyView[i], extensionsView[i],
          `Failed extensions at offset ${i}`);

      const signatureVerifyView = new Uint8Array(sct.signature);
      const signatureView = new Uint8Array(sig);

      assert.equal(signatureVerifyView.length, signatureView.length,
        'Incorrect signature length');
      for(let i = 0; i < signatureVerifyView.length; i++)
        assert.equal(signatureVerifyView[i], signatureView[i],
          `Failed signature at offset ${i}`);
    });
  });

  describe('#verify()', () => {
    it('should verify correct SignedCertificateTimestamp', () => {
      const sct = new CTUtils.SignedCertificateTimestamp(CTUtils.Version.v1,
        logId, 1518094243621, new ArrayBuffer(0), sig, false, cert);

      return sct.verify(pubKey).then((res) => {
        assert.equal(res, true, 'Cannot verify');
      });
    });

    it('should detect incorrect SignedCertificateTimestamp', () => {
      sctBin[0]++;
      const sct = CTUtils.SignedCertificateTimestamp.fromBinary(sctBin.buffer);
      sctBin[0]--;

      return sct.verify(pubKey).then((res) => {
        assert.equal(res, false, 'Cannot detect');
      });
    });
  });
});
