/**
 * Certificate Transparency Utilities
 * CertHelper class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import CTLogHelper from './CTLogHelper';
import TimestampedEntry from './TimestampedEntry';
import MerkleTreeLeaf from './MerkleTreeLeaf';
import SignedCertificateTimestamp from './SignedCertificateTimestamp';
import PreCert from './PreCert';
import { LogEntryType, MerkleLeafType } from './Enums';
import * as pvutils from 'pvutils';

/**
 * CertHelper class
 */
export default class CertHelper {
  /**
   * Generate a key hash from a certificate.
   * This is the key hash as defined in RFC6962. Please note that you do not
   * always need the certificate of the final issuing CA since a precertificate
   * can be signed by a certificate with the CT EKU.
   * @param {pkijs.Certificate} cert - The certificate whose key hash will be
   * generated.
   * @return {Promise<ArrayBuffer>} A promise that is resolved with the key
   * hash.
   */
  static getKeyHash(cert) {
    const webcrypto = pkijs.getEngine();

    return webcrypto.subtle.digest({
      name: 'SHA-256'
    }, cert.subjectPublicKeyInfo.toSchema().toBER(false));
  }

  /**
   * Extract a list of SCTs from a certificate.
   * @param {pkijs.Certificate} cert - The certificate to extract the SCTs from.
   * @param {ArrayBuffer} issuerKeyHash - The issuer key hash. For more
   * information, please see the getKeyHash() documentation. If this is null,
   * then the SCTs will be extracted but the cert field will not be populated.
   * This is useful if you want to extract the information from the SCT but you
   * will not be able to perform any kind of validation.
   * @return {Array<SignedCertificateTimestamp>} An array of
   * SignedCertificateTimestamp objects or null if no SCTs exist in the
   * certificate.
   */
  static extractSCTFromCert(cert, issuerKeyHash = null) {
    let sctExt = null;

    cert.extensions.forEach(ext => {
      if(ext.extnID === '1.3.6.1.4.1.11129.2.4.2')
        sctExt = ext;
    });

    if(sctExt === null)
      return null;

    const asn1 = asn1js.fromBER(sctExt.extnValue.valueBlock.valueHex);
    if((asn1.offset === -1) || !(asn1.result instanceof asn1js.OctetString))
      return null;

    const preCert = CertHelper.certToPreCert(cert, issuerKeyHash);

    const sctList = [];
    let parseBlock = asn1.result.valueBlock.valueHex;
    let parseBlockView = new Uint8Array(parseBlock);
    const totalLen = (parseBlockView[0] << 8) + parseBlockView[1];
    let parsedLen = 0;

    parseBlock = parseBlock.slice(2);

    while(parsedLen < totalLen) {
      parseBlockView = new Uint8Array(parseBlock);
      const sctLen = (parseBlockView[0] << 8) + parseBlockView[1];

      sctList.push(SignedCertificateTimestamp.fromBinary(parseBlock.slice(2,
        sctLen), LogEntryType.precert_entry, preCert));
      parseBlock = parseBlock.slice(2 + sctLen);
      parsedLen += (2 + sctLen);
    }

    return sctList;
  }

  /**
   * Generate a PreCert from a certificate.
   * This will not generate a precertificate but a PreCert structure.
   * If there is an SCT list extension in the certificate, then this will be
   * removed.
   * @param {pkijs.Certificate} cert - The certificate from which the PreCert
   * will be generated.
   * @param {ArrayBuffer} issuerKeyHash - The issuer key hash. For more
   * information, please see the getKeyHash() documentation.
   * @return {PreCert} A PreCert object.
   */
  static certToPreCert(cert, issuerKeyHash) {
    /* First make a copy of the cert */
    let asn1 = asn1js.fromBER(cert.toSchema().toBER(false));
    const workingCert = new pkijs.Certificate({ schema: asn1.result });

    /* Remove SCT list */
    const sctListIndex = workingCert.extensions.findIndex(ext =>
      ext.extnID === '1.3.6.1.4.1.11129.2.4.2');

    if(sctListIndex !== -1)
      workingCert.extensions.splice(sctListIndex, 1);

    return new PreCert(issuerKeyHash, workingCert.encodeTBS().toBER(false));
  }

  /**
   * Validate the SCTs from a certificate.
   * Note that this validates the SCTs that were generated from a precertificate
   * and are embedded in a certificate. To validate an SCT that was generated
   * for a certificate, create a SignedCertificateTimestamp object and use the
   * verify() method.
   * @param {pkijs.Certificate} cert - The certificate that will be validated.
   * @param {ArrayBuffer} issuerKeyHash - The issuer key hash. For more
   * information, please see the getKeyHash() documentation.
   * @param {Array<CTLog>} ctLogs - An array of CTLog objects. The only logs
   * that need to be included are the logs that issued the SCTs. Furthermore,
   * the only fields used are the logId and the public key of the log.
   * @return {Promise<Boolean>} A promise that is resolved with the result of
   * the validation. If there are no SCTs in the certificate, then the result
   * of the validation will be true. If an SCT belongs to a log that is not
   * included in ctLogs, then the result will be false;
   */
  static validateCertSCT(cert, issuerKeyHash, ctLogs) {
    const logHelper = new CTLogHelper(ctLogs);
    const sctList = CertHelper.extractSCTFromCert(cert, issuerKeyHash);

    if(sctList.length === 0)
      return Promise.resolve(true);

    /*
     * We first check if all public keys exist and then we validate the
     * SCTs. This requires double work in finding the correct log from the
     * list, but we avoid starting a number of verifications if a single
     * log is missing.
     */
    for(const sct of sctList)
      if(logHelper.findById(sct.logId) == null)
        return Promise.resolve(false);

    const validations = [];
    sctList.forEach(sct => {
      const log = logHelper.findById(sct.logId);
      validations.push(sct.verify(log.pubKey));
    });

    return Promise.all(validations).then(res => {
      let ret = true;

      res.forEach(r => {
        ret &= r;
      });

      return ret;
    });
  }

  /**
   * Verify the inclusion of an SCT in a log.
   * @param {SignedCertificateTimestamp} sct - The SCT that will be checked.
   * Even if it is not required for other operations, the type and cert fields
   * must be set.
   * @param {Array<CTLog>} ctLogs - An array of CTLog objects. The only log
   * that needs to be included is the log that issued the SCT. Furthermore,
   * the only fields used are the url, the logId and the public key of the log.
   * @return {Promise<Boolean>} A promise that is resolved with the result of
   * the verification.
   */
  static verifySCTInclusion(sct, ctLogs) {
    const logHelper = new CTLogHelper(ctLogs);

    const log = logHelper.findById(sct.logId);
    if(log === null)
      return Promise.resolve(false);

    const timestampedEntry = new TimestampedEntry(sct.timestamp, sct.type,
      sct.cert, sct.extensions);
    const merkleTreeLeaf = new MerkleTreeLeaf(sct.version,
      MerkleLeafType.timestamped_entry, timestampedEntry);

    let sequence = Promise.resolve();

    sequence = sequence.then(() => log.getSTH());
    sequence = sequence.then(sth =>
      log.getProofByLeaf(sth.treeSize, merkleTreeLeaf));
    sequence = sequence.then(res => {
      return true;
    });
    sequence = sequence.catch(e => {
      return false;
    });

    return sequence;
  }
}
