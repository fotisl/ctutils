/**
 * Certificate Transparency Utilities
 * SCT class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import CTLog from './CTLog';
import { LogEntryType, SignatureType } from './Enums';
import { uint64ToArrayBuffer, arrayBufferToUint64 } from './Common';

/**
 * SCT class
 */
export default class SignedCertificateTimestamp {
  /**
   * Construct an SCT object.
   * @param {number} version - The version of the SCT, currently only 1 is
   * defined and supported.
   * @param {ArrayBuffer} logId - The id of the log.
   * @param {number} timestamp - The timestamp of the SCT.
   * @param {ArrayBuffer} extensions - The extensions.
   * @param {ArrayBuffer} signature - The signature.
   * @param {number} type - The type of the entry, either
   * LogEntryType.x509_entry or LogEntryType.precert_entry.
   * @param {ArrayBuffer} cert - The certificate or precertificate
   * for this SCT.
   */
  constructor(version, logId, timestamp, extensions, signature,
    type = LogEntryType.x509_entry, cert = null) {
    /**
     * @type {number}
     * @description The version of the SCT.
     */
    this.version = version;
    /**
     * @type {ArrayBuffer}
     * @description The id of the log.
     */
    this.logId = logId;
    /**
     * @type {number}
     * @description The timestamp of the SCT.
     */
    this.timestamp = timestamp;
    /**
     * @type {ArrayBuffer}
     * @description The extensions.
     */
    this.extensions = extensions;
    /**
     * @type {ArrayBuffer}
     * @description The signature.
     */
    this.signature = signature;
    /**
     * @type {number}
     * @description The type of the entry.
     */
    this.type = type;
    /**
     * @type {ArrayBuffer}
     * @description The certificate or precertificate for this SCT.
     */
    this.cert = cert;
  }

  /**
   * Encode the SCT and get the binary representation.
   * @return {ArrayBuffer} An ArrayBuffer containing the binary representation
   * of the SCT.
   */
  toBinary() {
    const logIdView = new Uint8Array(this.logId);
    const extensionsView = new Uint8Array(this.extensions);
    const signatureView = new Uint8Array(this.signature);

    /*
     * Total size is calculated from the following:
     * 1 byte: version
     * 32 bytes: log id
     * 8 bytes: timestamp
     * 2 bytes: length of extensions
     * extensionsView.length bytes: the extensions
     * signatureView.length bytes: the signature
     */
    const sctLen = 1 + 32 + 8 + 2 + extensionsView.length +
      signatureView.length;
    const sct = new ArrayBuffer(sctLen);
    const sctView = new Uint8Array(sct);

    sctView[0] = this.version;

    sctView.set(logIdView, 1);

    sctView.set(new Uint8Array(uint64ToArrayBuffer(this.timestamp)), 33);

    sctView[41] = (extensionsView.length >> 8) & 0xff;
    sctView[42] = extensionsView.length & 0xff;

    sctView.set(extensionsView, 43);

    sctView.set(signatureView, 43 + extensionsView.length);

    return sct;
  }

  /**
   * Parse a binary SCT and return a new SCT object.
   * @param {ArrayBuffer} sctBin - The binary SCT.
   * @param {number} type - The type of the entry.
   * @param {ArrayBuffer} cert - The certificate or precertificate
   * for this SCT.
   * @return {SCT} An SCT object containing all information from the binary SCT.
   */
  static fromBinary(sctBin, type = LogEntryType.x509_entry, cert = null) {
    const sctBinView = new Uint8Array(sctBin);

    const version = sctBinView[0];

    const logId = sctBinView.slice(1, 33).buffer;

    const timestamp = arrayBufferToUint64(sctBinView.slice(33, 41).buffer);

    const extLen = (sctBinView[41] << 8) + sctBinView[42];
    const extensions = sctBinView.slice(43, 43 + extLen).buffer;

    const signature = sctBinView.slice(43 + extLen).buffer;

    return new SignedCertificateTimestamp(version, logId, timestamp, extensions,
      signature, type, cert);
  }

  /**
   * Verify the signature of an SCT.
   * @param {(ArrayBuffer|CTLog)} log - The public key of the log as an
   * ArrayBuffer, or a CTLog object.
   * @return {Promise.<Boolean>} A promise that is resolved with the result
   * of the verification.
   */
  verify(log) {
    let pubKey;
    if(log instanceof CTLog) {
      pubKey = log.pubKey;
    } else if(log instanceof ArrayBuffer) {
      pubKey = log;
    } else {
      return Promise.reject(new Error('Unknown key type'));
    }

    let sequence = Promise.resolve();
    const signatureView = new Uint8Array(this.signature);

    const certView = new Uint8Array(this.cert);
    const extensionsView = new Uint8Array(this.extensions);

    const dataStructLen = 17 + certView.length + extensionsView.length;
    const dataStruct = new ArrayBuffer(dataStructLen);
    const dataStructView = new Uint8Array(dataStruct);

    /*
     * Prepare the struct with the data that was signed.
     */
    dataStructView[0] = this.version;

    dataStructView[1] = SignatureType.certificate_timestamp;

    dataStructView.set(new Uint8Array(uint64ToArrayBuffer(this.timestamp)), 2);

    dataStructView[10] = (this.type >> 8) & 0xff;
    dataStructView[11] = this.type & 0xff;

    dataStructView[12] = (certView.length >> 16) & 0xff;
    dataStructView[13] = (certView.length >> 8) & 0xff;
    dataStructView[14] = certView.length & 0xff;

    dataStructView.set(certView, 15);

    dataStructView[16 + certView.length] =
      (extensionsView.length >> 8) & 0xff;
    dataStructView[16 + certView.length + 1] =
      extensionsView.length & 0xff;

    if(extensionsView.length > 0)
      dataStructView.set(extensionsView, 18 + certView.length);

    /*
     * Per RFC6962 all signatures are either ECDSA with the NIST P-256 curve
     * or RSA (RSASSA-PKCS1-V1_5) with SHA-256.
     */
    const isECDSA = signatureView[1] === 3;

    const pubKeyView = new Uint8Array(pubKey);

    const webcrypto = pkijs.getEngine();

    sequence = sequence.then(() => {
      let opts;

      if(isECDSA) {
        opts = {
          name: 'ECDSA',
          namedCurve: 'P-256'
        };
      } else {
        opts = {
          name: 'RSASSA-PKCS1-v1_5',
          hash: {
            name: 'SHA-256'
          }
        };
      }

      return webcrypto.subtle.importKey('spki', pubKeyView, opts, false,
        ['verify']);
    });

    sequence = sequence.then(publicKey => {
      let opts;

      if(isECDSA) {
        opts = {
          name: 'ECDSA',
          hash: {
            name: 'SHA-256'
          }
        };
      } else {
        opts = {
          name: 'RSASSA-PKCS1-v1_5'
        };
      }

      if(isECDSA) {
        /*
         * Convert from a CMS signature to a webcrypto compatible one.
         */
        const asn1 = asn1js.fromBER(this.signature.slice(4));
        const ecdsaSig = pkijs.createECDSASignatureFromCMS(asn1.result);
        return webcrypto.subtle.verify(opts, publicKey, ecdsaSig, dataStruct);
      } else {
        return webcrypto.subtle.verify(opts, publicKey, this.signature.slice(4),
          dataStruct);
      }
    });

    return sequence;
  }

  /**
   * Get the signature algorithm.
   * @return {number} The signature algorithm of the digitally signed struct,
   * as defined in RFC5246, i.e. 1 for RSA and 3 for ECDSA.
   */
  getSignatureAlgorithm() {
    const signatureView = new Uint8Array(this.signature);

    return signatureView[1];
  }

  /**
   * Get the internal signature of the SCT.
   * @return {ArrayBuffer} The internal signature of the digitally signed
   * struct.
   */
  getInternalSignature() {
    return this.signature.slice(4);
  }

  /**
   * Set the signature of the SCT.
   * @param {number} algorithm - The signature algorithm as defined in RFC5246.
   * @param {ArrayBuffer} signature - The internal signature.
   */
  setSignature(algorithm, signature) {
    const newSigView = new Uint8Array(signature);
    this.signature = new ArrayBuffer(4 + newSigView.length);
    const sigView = new Uint8Array(this.signature);

    /* Hash algorithm is always SHA256 */
    sigView[0] = 4;
    sigView[1] = algorithm;
    sigView[2] = (newSigView.length >> 8) & 0xff;
    sigView[3] = newSigView.length & 0xff;

    for(let i = 0; i < newSigView.length; i++)
      sigView[4 + i] = newSigView[i];
  }
}
