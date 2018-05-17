/**
 * Certificate Transparency Utilities
 * PreCert class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * PreCert class
 * Please note that this is a precert as defined in section 3.2 of RFC6962
 * and not a certificate with the poison extension.
 */
export default class PreCert {
  /**
   * Construct a PreCert.
   * @param {ArrayBuffer} issuerHash - The issuer hash.
   * @param {ArrayBuffer} tbs - The TBS struct.
   */
  constructor(issuerHash, tbs) {
    /**
     * @type {ArrayBuffer}
     * @description The issuer hash.
     */
    this.issuerHash = issuerHash;
    /**
     * @type {ArrayBuffer}
     * @description The TBS struct.
     */
    this.tbs = tbs;
  }

  /**
   * Encode the PreCert and get the binary representation.
   * @return {ArrayBuffer} An ArrayBuffer containing the binary representation
   * of the PreCert.
   */
  toBinary() {
    const issuerHashView = new Uint8Array(this.issuerHash);
    const tbsView = new Uint8Array(this.tbs);

    const preCertLen = 32 + 3 + tbsView.length;
    const preCert = new ArrayBuffer(preCertLen);
    const preCertView = new Uint8Array(preCert);

    preCertView.set(issuerHashView);

    preCertView[32] = (tbsView.length >> 16) & 0xff
    preCertView[33] = (tbsView.length >> 8) & 0xff
    preCertView[34] = tbsView.length & 0xff

    preCertView.set(tbsView, 35);

    return preCertView;
  }

  /**
   * Parse a binary Precert and return a new object.
   * @param {ArrayBuffer} preCertBin - The binary PreCert.
   * @return {PreCert} The PreCert object.
   */
  static fromBinary(preCertBin) {
    return new PreCert(preCertBin.slice(0, 32),
      preCertBin.slice(35));
  }
}
