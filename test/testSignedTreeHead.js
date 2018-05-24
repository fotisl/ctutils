/**
 * Certificate Transparency Utilities
 * Test SignedTreeHead
 *
 * By Fotis Loukos <me@fotisl.com>
 */

require('babel-polyfill');
const assert = require('assert');
const pvutils = require('pvutils');
const CTUtils = require('..');
const WebCrypto = require('node-webcrypto-ossl');

const webcrypto = new WebCrypto();
CTUtils.setWebCrypto(webcrypto);

describe('SignedTreeHead', () => {
  describe('#verify()', () => {
    it('should verify correct ECDSA SignedTreeHead with public key', () => {
      const rootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        '7IXxX5gNLhKS4vANtkO0gPAqx9YRra17IJfzMJM2AiQ='));

      const signature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAMARjBEAiBktm+l47z01OLaAAwUtDGNr+xzjJJRG5aNBcx3fBxxBQIgTlC/Ck3cSLu' +
        'K23N+/7BQxv4xfQbF1RH7pG/6S3N6Z4U='));

      const pubKey = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp3' +
        '7MtRxTmACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA=='));

      const sth = new CTUtils.SignedTreeHead(170761442, 1526202484196, rootHash,
        signature, CTUtils.Version.v1);

      return sth.verify(pubKey).then(res => {
        assert.equal(res, true, 'Cannot verify');
      });
    });

    it('should verify correct ECDSA SignedTreeHead with CTLog', () => {
      const rootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        '7IXxX5gNLhKS4vANtkO0gPAqx9YRra17IJfzMJM2AiQ='));

      const signature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAMARjBEAiBktm+l47z01OLaAAwUtDGNr+xzjJJRG5aNBcx3fBxxBQIgTlC/Ck3cSLu' +
        'K23N+/7BQxv4xfQbF1RH7pG/6S3N6Z4U='));

      const pubKey = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp3' +
        '7MtRxTmACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA=='));

      const log = new CTUtils.CTLog('ct.googleapis.com/pilot/', pubKey);

      const sth = new CTUtils.SignedTreeHead(170761442, 1526202484196, rootHash,
        signature, CTUtils.Version.v1);

      return sth.verify(log).then(res => {
        assert.equal(res, true, 'Cannot verify');
      });
    });

    it('should detect incorrect ECDSA SignedTreeHead', () => {
      const rootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        '7IXxX5gNLhKS4vANtkO0gPAqx9YRra17IJfzMJM2AiQ='));

      const signature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAMARjBEAiBktm+l47z01OLaAAwUtDGNr+xzjJJRG5aNBcx3fBxxBQIgTlC/Ck3cSLu' +
        'K23N+/7BQxv4xfQbF1RH7pG/6S3N6Z4U='));

      const pubKey = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp3' +
        '7MtRxTmACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA=='));

      const verSignature = new Uint8Array(signature);
      verSignature[5]++;
      const sth = new CTUtils.SignedTreeHead(170761442, 1526202484196, rootHash,
        signature, CTUtils.Version.v1);

      return sth.verify(pubKey).then(res => {
        assert.equal(res, false, 'Cannot detect');
      });
    });

    it('should verify correct RSA SignedTreeHead', () => {
      const rootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'I7PzqT8cEPjlfgOx3/2VxnuO5BTIJ6Zf8OM8DAwGhuM='));

      const signature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAEBAAgJjfMWJ0agR0VCpB1v8UJs3X8H3dPU8C0NmUMtMAdAm27tgiDcpDECHCMrJbI' +
        'Iy7v+y1p4zVGC6eWf1Tew+W+O32WinshHb9th7lLNlQ5yJUKW5UtMTJxW/BiFpHO75+' +
        'WXsajb4EyTPkoJ1M2qxDX/cK/hSb2ar0W7G9weRaw7WetwEAG7pv2j/tnUUGXHWfnNk' +
        'g6f40GkwSaGfY9Xw9gaZDeUawvS8T61qODsaZprWDsBAWaClaaelrmlx0kkZBnMP/LK' +
        'KSlywrTNEt3Ow1oKBqT3nL5A2fTPoRfsF+1OGyy2iokX2pI1ZLBRS4v4rqMce/dgzXx' +
        'rS6OUUINHfLA='));

      const pubKey = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpS' +
        'j/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7fr' +
        'GlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6O' +
        'NaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iB' +
        'zf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwj' +
        'feG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB'));

      const sth = new CTUtils.SignedTreeHead(90161, 1488320541206, rootHash,
        signature, CTUtils.Version.v1);

      return sth.verify(pubKey).then(res => {
        assert.equal(res, true, 'Cannot verify');
      });
    });

    it('should detect incorrect RSA SignedTreeHead', () => {
      const rootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'I7PzqT8cEPjlfgOx3/2VxnuO5BTIJ6Zf8OM8DAwGhuM='));

      const signature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAEBAAgJjfMWJ0agR0VCpB1v8UJs3X8H3dPU8C0NmUMtMAdAm27tgiDcpDECHCMrJbI' +
        'Iy7v+y1p4zVGC6eWf1Tew+W+O32WinshHb9th7lLNlQ5yJUKW5UtMTJxW/BiFpHO75+' +
        'WXsajb4EyTPkoJ1M2qxDX/cK/hSb2ar0W7G9weRaw7WetwEAG7pv2j/tnUUGXHWfnNk' +
        'g6f40GkwSaGfY9Xw9gaZDeUawvS8T61qODsaZprWDsBAWaClaaelrmlx0kkZBnMP/LK' +
        'KSlywrTNEt3Ow1oKBqT3nL5A2fTPoRfsF+1OGyy2iokX2pI1ZLBRS4v4rqMce/dgzXx' +
        'rS6OUUINHfLA='));

      const pubKey = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpS' +
        'j/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7fr' +
        'GlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6O' +
        'NaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iB' +
        'zf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwj' +
        'feG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB'));

      const verSignature = new Uint8Array(signature);
      verSignature[5]++;
      const sth = new CTUtils.SignedTreeHead(90161, 1488320541206, rootHash,
        signature, CTUtils.Version.v1);

      return sth.verify(pubKey).then(res => {
        assert.equal(res, false, 'Cannot detect');
      });
    });
  });

  describe('#verifyConsistency()', () => {
    it('should verify consistent STHs', () => {
      const firstRootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        '6S3D8D5Q8NV5tK3CoG8TK+6rSEG7cXpgpVWqMQaIQJ8='));
      const firstSignature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAMARjBEAiBz2MSIUxbtCarz9gdxHqGDxpKCbjL7T5h6DEIhtGKDAQIgQs/TZ96jUsf' +
        'FX5TtkmtxXz4+vnpY4rW/VgCiCx67Yn4='));
      const secondRootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'mUlAb0rslEHouTTTFyDP4vQO/eIRqE8jInH8mucA39M='));
      const secondSignature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAMARzBFAiEA0EBSQV04N21UW5OOYz/6uiMlmtoPzjaTXkx8mJP7O94CIHrQJj8izOX' +
        'Uwm1JEzxN1ttR+tB3I+g48BPFkf81+NER'));
      const first = new CTUtils.SignedTreeHead(16444754, 1526367328650,
        firstRootHash, firstSignature, CTUtils.Version.v1);
      const second = new CTUtils.SignedTreeHead(16447636, 1526370936098,
        secondRootHash, secondSignature, CTUtils.Version.v1);
      const proofs = [];
      const b64Proofs = [
        'GfgUCq5pXIuh73fnDJUb0S64a1slZtXg8zlzK/fUpZI=',
        'EYq9SFQp8MoARFevnAdygE2Tu195PN7CxJchGSfpCfM=',
        'HH4j+gtRTV3rHyX1YNJI3t02ymealM9y6pG+Lik3Gg0=',
        'gbLLA1hCLR9fLDnlLvBvRGYO0yImF7B67WbSAvqr74A=',
        'oPDj7RRLmgqiIDeU5nc01vxlozz71zwrPzTIxjB9fSg=',
        'aYhCIv6Debl1joA5IPvUkEcxXYJxGiwGFaoNlZkse7o=',
        'nelm9OnVACDlCaiVHCunBGp9YVkhaURfmo1AnIzSs6o=',
        'vXEfahB7EyEErnFVVF+tdRyVG6V+dPxqwWJk2ov0OaQ=',
        'CU1mwi8t2zxJs/yGD6mbl9m7BQ/WKWCobyqrRUey6OU=',
        'zdcqHoTxpDf93hT5b12pNEOWptRblwwvpQ02Ec7+Vaw=',
        '84yTmprYU9gaz3WmRBh4rxwkwgNcFw9GqPRvpsxGRtY=',
        'J3sqEFzMu4+hHRcGSQDduT2uRHPBuASWPOzhRx4uH6k=',
        'bAaUza+ovsYOjq1x5iivqRfKNGPbqIGhPrYDDxVONKY=',
        's3kKZn0XeyLdqmPO3GIXy+7NfAJHUWkSdOJoBca+RaI=',
        'OwMsUuW6n89cgBN5lXcc0n4b56a+Cf9qbEMqswwQZN8=',
        '7JeM6ZM735FiP9Oaz/uatrdWWLTqKniSeioOzuVUCtg=',
        'sbmlvlUXeq/JapoVdVCcp3ievD6IlZrut/Z9yqh76Z8=',
        'SBv3+jTnmLJ0ssGawyrik3r8Q1XvfmRoKZ1XRXV6PDU=',
        'kD1mHZzJzODGPRwryE4Q2F/FjhHDe88eQ3PkT7nh2Rw=',
        'D8da4qJEsYH/MvQVRIzhCqCdbUxJqMG/LSgKvvKQ94A=',
        'X0H/hecm8dBP9TmBCrYOIc0T+o53Po+TBmLsaz2A32w=',
        '4BmXk7bMyQWV3cj14p/4jsZnob53XEULsISzf155AaI='
      ];
      b64Proofs.forEach(bp => {
        proofs.push(pvutils.stringToArrayBuffer(pvutils.fromBase64(bp)));
      });

      return first.verifyConsistency(second, proofs).then(res => {
        assert.equal(res, true, 'Cannot verify');
      });
    });

    it('should detect inconsistent STHs', () => {
      /* Venafi log inconsistency */
      const firstRootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'I7PzqT8cEPjlfgOx3/2VxnuO5BTIJ6Zf8OM8DAwGhuM='));
      const firstSignature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAEBAAgJjfMWJ0agR0VCpB1v8UJs3X8H3dPU8C0NmUMtMAdAm27tgiDcpDECHCMrJbI' +
        'Iy7v+y1p4zVGC6eWf1Tew+W+O32WinshHb9th7lLNlQ5yJUKW5UtMTJxW/BiFpHO75+' +
        'WXsajb4EyTPkoJ1M2qxDX/cK/hSb2ar0W7G9weRaw7WetwEAG7pv2j/tnUUGXHWfnNk' +
        'g6f40GkwSaGfY9Xw9gaZDeUawvS8T61qODsaZprWDsBAWaClaaelrmlx0kkZBnMP/LK' +
        'KSlywrTNEt3Ow1oKBqT3nL5A2fTPoRfsF+1OGyy2iokX2pI1ZLBRS4v4rqMce/dgzXx' +
        'rS6OUUINHfLA='));
      const secondRootHash = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'sMnqsYxLYyKdF7QNqplWgnIJk6WBsuqlEGo0aNHHhRg='));
      const secondSignature = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        'BAEBAIXJw+INMcxEzrsW3+tzgxiE2jP8sJZN5HYwO3MmuFHy5t57lJqPADYEFBIfx7c' +
        'EEGyp0RQLb6Wonvkq4xhsANt0xXCQQw1STxRKixnaYtSnEkoVJfWXPAVyjUqFPx+ryO' +
        'HtdocMGlf60rt4UmGK0rhy9XTCrktYFkzG9ZPrGujGDvXIeBnIaarbU0L5g224rsdLv' +
        'DXwpRopHpHinomsc5W+ReA+eQ38WGBHkz33e/+YPJQGd/L3EaDN3da0VIEYNHY5AGW/' +
        'Yq7rU6cD+dHH9mL1OK971/HZ362aEnBBZ47zi/1OzANeKdT1tyB+db7VpXhScJxw1o0' +
        'G3T0V0P+lM4o='));
      const first = new CTUtils.SignedTreeHead(90161, 1488320541206,
        firstRootHash, firstSignature, CTUtils.Version.v1);
      const second = new CTUtils.SignedTreeHead(90167, 1488321064440,
        secondRootHash, secondSignature, CTUtils.Version.v1);
      const proofs = [];
      const b64proofs = [
        'r+r7qrYh4i9lWa1nzVO86nj+9c6BGZq5i36IRzgPGl4=',
        'NPLfppxk5a1xQZb/tmCK3oJ/WFflOaxx4pNE49Tf+8Y=',
        'U0IGCc5N616P/zKPQVkFZkYdRoSBmLipCgspE0vNLeE=',
        'kZiqCHdVXWXLAmFtPPm6tNUBm3ciQY7KTkBIPdPyP50=',
        'im9E++S7hURbeazY1bHGqxx6/5zYmDmpLhCU3lAvGOM=',
        'VH8nj3DKzwv9v3bcQeDKjw4a0H+GbIm1SIxU0z3J/1E=',
        '2eQpspAlOaHniWW6exNICgPfge2u0BHXAU0bJoCxy+c=',
        'jsEyi+238H+/SNiDNmoNeGTPeMkBEeM55WNKuuPrfeY=',
        'rcxt0aKSfv5MGCDJSwt6WDZffq9Nmp4SpQm5Xr376Lo='
      ];
      b64proofs.forEach(bp => {
        proofs.push(pvutils.stringToArrayBuffer(pvutils.fromBase64(bp)));
      });

      return first.verifyConsistency(second, proofs).then(res => {
        assert.equal(res, false, 'Cannot detect');
      });
    });
  });
});
