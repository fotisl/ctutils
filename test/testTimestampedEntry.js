/**
 * Certificate Transparency Utilities
 * Test TimestampedEntry
 *
 * By Fotis Loukos <me@fotisl.com>
 */

require('babel-polyfill');
const assert = require('assert');
const fs = require('fs');
const CTUtils = require('..');

const certBuffer = fs.readFileSync('test/cert.der');
const certBin = new Uint8Array(certBuffer);
const timestampedEntryBuffer = fs.readFileSync('test/timestampedEntry.bin');
const timestampedEntryBin = new Uint8Array(timestampedEntryBuffer);

describe('TimestampedEntry', () => {
  describe('#toBinary()', () => {
    it('should encode correctly', () => {
      const timestampedEntry = new CTUtils.TimestampedEntry(1518292105091,
        CTUtils.LogEntryType.x509_entry, certBin.buffer, new ArrayBuffer(0));

      const timestampedEntryVerify = new Uint8Array(
        timestampedEntry.toBinary());

      assert.equal(timestampedEntryVerify.length, timestampedEntryBin.length,
        'Incorrect encoded length');

      for(let i = 0; i < timestampedEntryBin.length; i++)
        assert.equal(timestampedEntryVerify[i], timestampedEntryBin[i],
          `Failed at offset ${i}`);
    });
  });

  describe('#fromBinary()', () => {
    it('should decode correctly', () => {
      const timestampedEntry = CTUtils.TimestampedEntry.fromBinary(
        timestampedEntryBin.buffer);
      const certVerify = new Uint8Array(timestampedEntry.cert);

      assert.equal(timestampedEntry.timestamp, 1518292105091,
        'Incorrect timestamp');

      assert.equal(timestampedEntry.type, CTUtils.LogEntryType.x509_entry,
        'Incorrect type');

      assert.equal(certVerify.length, certBin.length,
        'Incorrect certificate length');

      for(let i = 0; i < certBin.length; i++)
        assert.equal(certVerify[i], certBin[i],
          `Failed certificate at offset ${i}`);
    });
  });
});
