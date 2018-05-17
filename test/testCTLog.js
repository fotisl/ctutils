/**
 * Certificate Transparency Utilities
 * Test CTLog
 *
 * By Fotis Loukos <me@fotisl.com>
 */

require('babel-polyfill');
const assert = require('assert');
const pvutils = require('pvutils');
const CTUtils = require('..');

const url = 'ct.googleapis.com/pilot/';
const pubKey = pvutils.stringToArrayBuffer(pvutils.fromBase64(
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBR' +
  'uiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA=='));
const logId = pvutils.stringToArrayBuffer(pvutils.fromBase64(
  'pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA='));

const log = new CTUtils.CTLog(url, pubKey);

describe('CTLog', () => {
  describe('#generateId()', () => {
    it('should generate logId correctly', () => {
      log.generateId().then(res => {
        assert.equal(res, true, 'Generation failed');

        const logIdView = new Uint8Array(logId);
        const logIdVerify = new Uint8Array(log.logId);

        assert.equal(logIdVerify.length, logIdView.length,
          'Incorrect logId length');

        for(let i = 0; i < logIdView.length; i++)
          assert.equal(logIdVerify[i], logIdView[i],
            `Failed logId at offset ${i}`);
      });
    });
  });

  describe('#getBaseUrl()', () => {
    it('should generate correct base url', () => {
      assert.equal(log.getBaseUrl(), 'https://ct.googleapis.com/pilot/ct/v1',
        'Cannot generate base url');
    });
  });
});
