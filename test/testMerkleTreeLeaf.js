/**
 * Certificate Transparency Utilities
 * Test MerkleTreeLeaf
 *
 * By Fotis Loukos <me@fotisl.com>
 */

require('babel-polyfill');
const assert = require('assert');
const fs = require('fs');
const pvutils = require('pvutils');
const CTUtils = require('..');

describe('MerkleTreeLeaf', () => {
  describe('#getHash()', () => {
    it('should hash leafs correctly', () => {
      const certBuffer = fs.readFileSync('test/cert.der');
      const cert = new Uint8Array(certBuffer);

      const hash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        '4Q6I4FH8rtU9GBYP0qMPcc0KY9bqE57pgzq3Anz+9vg='));

      const timestampedEntry = new CTUtils.TimestampedEntry(1518094243621,
        CTUtils.LogEntryType.x509_entry, cert.buffer, new ArrayBuffer(0));
      const merkleTreeLeaf = new CTUtils.MerkleTreeLeaf(CTUtils.Version.v1,
        CTUtils.MerkleLeafType.timestamped_entry, timestampedEntry);

      return merkleTreeLeaf.getHash().then(verifyHash => {
        const hashView = new Uint8Array(hash);
        const verifyHashView = new Uint8Array(verifyHash);

        assert.equal(verifyHashView.length, hashView.length,
          'Incorrect hash length');

        for(let i = 0; i < hashView.length; i++)
          assert.equal(verifyHashView[i], hashView[i],
            `Failed hash at offset ${i}`);
      });
    });
  });

  describe('#verifyInclusionByHash()', () => {
    const rootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
      'VQLsTJvc2eBnDEZhHeddXLGKgWDyG7A4JnchfiogoMk='));
    const signature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
      'BAMARjBEAiBAMCd1wKK98PUuz+lEDF8gMe3+IrH5BNhnAaFlQliZYwIgG93Ugdfeb3T' +
      'zxV+bHGR9CvMZbRHmpn2sbMyXupEwkwE='));
    const sth = new CTUtils.SignedTreeHead(173663002, 1526380010685, rootHash,
      signature, CTUtils.Version.v1);

    const auditPath = [];
    const b64AuditPath = [
      '6O0a48HKBUDVlLORD8EFxI28mMlTHu8jjqXG/17S/9A=',
      'mVBYZQPYS6vWbXZpLvSAEuOMfzvn7YFOgJjW4kSsRcE=',
      'ieWMKM+T+BX2VJtdvwTZaf5RCzQ+rzvKuaAKqLXFZMc=',
      'lHH3J7mkVmtmKRYHMNVIZByEXlYOOp/HeJ6pWVFl7Gw=',
      'Adxq9INKDMp5e/v1KZOTea3xwwiCS/Fe5c6+57wpJ3s=',
      'sZ5Nd4ciG0CwQwC3a30B2ll0LCgzG/l9l7pj957y0HU=',
      'wpDDMVw0lyNA/zCG59tJXhA+RjX6KvmWjaKAviDsw6A=',
      'afrzJQvMZX0J9LPl8zX9AVt3iJjbTv0f0scU3yOxMD8=',
      'pKdF30qfYL9Tfh/+A78nuIMxigwtD3HouKbotVvk5gI=',
      '0AsWtC2MqoxvV+7RgGZM3e5J+LCpRFtMOR5mYunsf2U=',
      'IpCr5O8XeK/QsByIiRNRXRCUB50Ikz01EcAuFfDLx5A=',
      'qp2NlPmnklDvV3rfYJ4y8Z9Nftqt+y8/2cg5BLgBjnc=',
      'Ia+cA72/6sXNxAuChqIX4CH52iO5lX1kle/vaC2vUgw=',
      'shl6piFH2RyluQKAU98e3xM7buuLgrMoblw0xoPksB8=',
      'dWxfzTHWl0BShffs2ao1gfaw7DaLyw+OLGR+rM2knQA=',
      '4ObquTaYHT0T9frHPY2jqm642VyrrXyFFFHPtf3TY+c=',
      'YlxlGBM6hAwaCKQdpEcxyCSVi2SBqcaRjzOQQ3+1ysQ=',
      'OWVPadjdgmtXQiV+sguW3ytPnEROkpUesOCpWaUhGu8=',
      'C/nJb2umZSwxql341mm4BOqBPDma5zyX/vd4q89p1gs=',
      'TodM5dLc0BkUBEaLdvltqBemId0V3DAK3s/xG4s12us=',
      'xnHY/AkejowDpHbBECLM4uCqNGVxRBka3EE229p1WDs=',
      'tPWRkHc9dXt5sAUn4unMg/gyjIv5kxX0ZwBth48mUjA=',
      'z53QLHKnZwx2cRYFAYEfBHiqUCMsNokST2omnCrMxdc=',
      '90U/9/FzhAhyAbQhzGX7I70EDGI9bc/jVKwHhAMhXSY=',
      '+Xn7EJ7X5kh3dv4DN833fEd9qiPuSubOzBlC/+bljcY=',
      'kfPObi1pGw/9CyrB+Y/bPIaKMcbbyZZkG6lcY8/eEAU=',
      'ehMQm7G17NJM7ZAI9BqjCWCrT7QUdThiSi9IdJmGOCA=',
      'BfwgPIYshkKPBr9VCNtklzmzHEd71LfRvzyKCUGiApk='
    ];
    b64AuditPath.forEach(bp => {
      auditPath.push(pvutils.stringToArrayBuffer(pvutils.fromBase64(bp)));
    });

    const hash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
      '4Q6I4FH8rtU9GBYP0qMPcc0KY9bqE57pgzq3Anz+9vg='));

    it('should verify correct audit path', () => {
      return CTUtils.MerkleTreeLeaf.verifyInclusionByHash(sth, 73426506,
        auditPath, hash).then(res => {
        assert.equal(res, true, 'Cannot verify');
      });
    });

    it('should detect invalid audit path', () => {
      const hashView = new Uint8Array(auditPath[0]);
      hashView[0]++;

      return CTUtils.MerkleTreeLeaf.verifyInclusionByHash(sth, 73426506,
        auditPath, hash).then(res => {
        assert.equal(res, false, 'Cannot detect');
      });
    });
  });
});
