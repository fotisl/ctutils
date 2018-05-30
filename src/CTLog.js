/**
 * Certificate Transparency Utilities
 * CTLog class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import * as pvutils from 'pvutils';
import MerkleTreeLeaf from './MerkleTreeLeaf';
import SignedCertificateTimestamp from './SignedCertificateTimestamp';
import SignedTreeHead from './SignedTreeHead';
import { Version, LogEntryType } from './Enums';
import { paramsToQueryString } from './Common';
import { getFetch } from './Engines';

/**
 * An audit proof.
 * @typedef {Object} AuditProof
 * @property {number} index - The index of the leaf in the tree.
 * @property {Array<ArrayBuffer>} auditPath - The audit path.
 */

/**
 * An entry in the log.
 * @typedef {Object} LogEntry
 * @property {MerkleTreeLeaf} leaf - The merkle tree leaf.
 * @property {Array.<pkijs.Certificate>} extraData - The data pertaining to
 * the entry.
 */

/**
 * An entry in the log and the audit proof.
 * @typedef {Object} LogEntryAndProof
 * @property {MerkleTreeLeaf} leaf - The merkle tree leaf.
 * @property {Array.<pkijs.Certificate>} extraData - The data pertaining to
 * the entry.
 * @property {Array<ArrayBuffer>} auditPath - The audit path.
 */

/**
 * Load a cert from an offset at an ArrayBuffer, with it's length prepended.
 * @param {ArrayBuffer} buffer - The buffer with the certificate.
 * @param {number} offset - The offset to start looking for the certificate.
 * @return {Object} An object with a length member containing the length of
 * the certificate and a certificate object with the actual certificate.
 */
function extractCert(buffer, offset) {
  const bufferView = new Uint8Array(buffer);

  const length = (bufferView[offset] << 16) +
    (bufferView[offset + 1] << 8) + bufferView[offset + 2];

  let certificate;

  try {
    const asn1 = asn1js.fromBER(buffer.slice(offset + 3, offset + 3 + length));
    certificate = new pkijs.Certificate({schema: asn1.result});
  } catch(err) {
    return {
      length,
      certificate: null
    };
  }

  return {
    length,
    certificate
  };
}

/**
 * Parse extraData reply for a Certificate and return the chain.
 * @param {ArrayBuffer} extraData - The extra data.
 * @return {Array.<pkijs.Certificate>} An array of pkijs.Certificates.
 */
function parseCertExtraData(extraData) {
  const extraDataView = new Uint8Array(extraData);

  let offset = 3;
  let certs = [];

  while(offset < extraDataView.length) {
    const res = extractCert(extraData, offset);

    if(res.certificate !== null)
      certs.push(res.certificate);

    offset += (3 + res.length);
  }

  return certs;
}

/**
 * Parse extraData reply for a Precertificate and return the chain.
 * @param {ArrayBuffer} extraData - The extra data.
 * @return {Array.<pkijs.Certificate>} An array of pkijs.Certificates.
 */
function parsePrecertExtraData(extraData) {
  const extraDataView = new Uint8Array(extraData);

  let offset = 0;
  let certs = [];

  let res = extractCert(extraData, offset);
  if(res.certificate !== null)
    certs.push(res.certificate);
  offset += (3 + res.length);

  /* Move on to the chain */
  offset += 3;

  while(offset < extraDataView.length) {
    res = extractCert(extraData, offset);

    if(res.certificate !== null)
      certs.push(res.certificate);

    offset += (3 + res.length);
  }

  return certs;
}

/**
 * CTLog class
 */
export default class CTLog {
  /**
   * Construct a CTLog object.
   * @param {string} url - The url of the log.
   * @param {ArrayBuffer} pubKey - The public key of the log.
   * @param {number} version - The version of the log.
   * @param {ArrayBuffer} logId - The log id.
   * @param {number} maximumMergeDelay - The maximum merge delay.
   * @param {string} description - The description of the log.
   * @param {Array.<string>} operators - The operators of the log.
   */
  constructor(url, pubKey, version = Version.v1, logId = null,
    maximumMergeDelay = 0, description = null, operators = null) {
    if(version !== Version.v1)
      throw new Error('Unsupported CT version');

    /**
     * @type string
     * @description The url of the log.
     */
    this.url = url;
    /**
     * @type ArrayBuffer
     * @description The public key of the log.
     */
    this.pubKey = pubKey;
    /**
     * @type number
     * @description The version of the log.
     */
    this.version = version;
    /**
     * @type ArrayBuffer
     * @description The log id.
     */
    this.logId = logId;
    /**
     * @type number
     * @description The maximum merge delay.
     */
    this.maximumMergeDelay = maximumMergeDelay;
    /**
     * @type string
     * @description The description of the log.
     */
    this.description = description;
    /**
     * @type Array<string>
     * @description The operators of the log.
     */
    this.operators = operators;
  }

  /**
   * Generate the log id from the public key.
   * @param {string} algorithmOID - The OID of the algorithm used for signing.
   * If this is null, then a heuristic method based on the key size will
   * be used.
   * @return {Promise.<Boolean>} The result of the generation. This will
   * normally be true, and it's used to notify that the calculation has
   * finished.
   */
  generateId(algorithmOID = null) {
    let algorithmIdentifier;

    if(algorithmOID === null) {
      if(this.pubKey.byteLength === 91) {
        algorithmIdentifier = new pkijs.AlgorithmIdentifier({
          algorithmId: '1.2.840.10045.2.1'
        });
      } else if(this.pubKey.byteLength === 294) {
        algorithmIdentifier = new pkijs.AlgorithmIdentifier({
          algorithmId: '1.2.840.113549.1.1.1'
        });
      } else {
        return Promise.reject(new Error('Cannot identify algorithm'));
      }
    } else {
      algorithmIdentifier = new pkijs.AlgorithmIdentifier({
        algorithmId: algorithmOID
      });
    }

    const pubKeyInfo = new pkijs.PublicKeyInfo({
      algorithm: algorithmIdentifier,
      subjectPublicKey: new asn1js.BitString({
        valueHex: this.pubKey
      })
    });

    return pkijs.getEngine().subtle.digest({
      name: 'SHA-256'
    }, pubKeyInfo.subjectPublicKey.valueBlock.valueHex).then(id => {
      this.logId = id;

      return true;
    });
  }

  /**
   * Get the base url under which all calls are made.
   * @return {string} The base url
   */
  getBaseUrl() {
    let url;

    if(this.url.startsWith('https://'))
      url = this.url;
    else
      url = 'https://' + this.url;

    while(url.endsWith('/'))
      url = url.substr(0, url.length - 1);

    if(this.version === Version.v1)
      url = url + '/ct/v1';

    return url;
  }

  /**
   * Add a certificate.
   * @param {Array.<pkijs.Certificate>} certs - A list of certificates. The
   * first certificate is the end-entity certificate to be added, the second
   * chains to the first and so on (please check RFC6962 section 4.1).
   * @return {Promise.<SignedCertificateTimestamp>} A promise that is resolved
   * with the SCT.
   */
  addCertChain(certs) {
    const encCerts = [];

    certs.forEach(cert => {
      const schema = cert.toSchema().toBER(false);
      encCerts.push(pvutils.toBase64(pvutils.arrayBufferToString(schema)));
    });

    let sequence = getFetch()(this.getBaseUrl() + '/add-chain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chain: encCerts
      })
    });

    sequence = sequence.then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const logId = pvutils.stringToArrayBuffer(pvutils.fromBase64(res.id));
      const extensions = pvutils.stringToArrayBuffer(
        pvutils.fromBase64(res.extensions));
      const signature = pvutils.stringToArrayBuffer(
        pvutils.fromBase64(res.signature));

      return new SignedCertificateTimestamp(res.sct_version, logId,
        res.timestamp, extensions, signature, LogEntryType.x509_entry,
        certs[0].toSchema().toBER(false));
    });

    return sequence;
  }

  /**
   * Add a precertificate.
   * @param {Array.<pkijs.Certificate>} precerts - A list of certificates. The
   * first should be the precertificate to be added, the second chains to
   * the first and so on (please check RFC6962 section 4.1).
   * @return {Promise.<SignedCertificateTimestamp>} A promise that is resolved
   * with the SCT.
   */
  addPreCertChain(certs) {
    const encCerts = [];

    certs.forEach(cert => {
      const schema = cert.toSchema().toBER(false);
      encCerts.push(pvutils.toBase64(pvutils.arrayBufferToString(schema)));
    });

    let sequence = getFetch()(this.getBaseUrl() + '/add-pre-chain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chain: encCerts
      })
    });

    sequence = sequence.then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const logId = pvutils.stringToArrayBuffer(pvutils.fromBase64(res.id));
      const extensions = pvutils.stringToArrayBuffer(
        pvutils.fromBase64(res.extensions));
      const signature = pvutils.stringToArrayBuffer(
        pvutils.fromBase64(res.signature));

      return new SignedCertificateTimestamp(res.sct_version, logId,
        res.timestamp, extensions, signature, LogEntryType.precert_entry,
        certs[0].toSchema().toBER(false));
    });

    return sequence;
  }

  /**
   * Get the SignedTreeHead.
   * @return {Promise.<SignedTreeHead>} A promise that is resolved with the
   * SignedTreeHead.
   */
  getSTH() {
    let sequence = getFetch()(this.getBaseUrl() + '/get-sth');

    sequence = sequence.then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const rootHash = pvutils.stringToArrayBuffer(
        pvutils.fromBase64(res.sha256_root_hash));
      const signature = pvutils.stringToArrayBuffer(
        pvutils.fromBase64(res.tree_head_signature));

      return new SignedTreeHead(res.tree_size, res.timestamp, rootHash,
        signature, Version.v1);
    });

    return sequence;
  }

  /**
   * Get the consistency proof between two signed tree heads.
   * @param {(number|SignedTreeHead)} first - The first signed tree head or its
   * size.
   * @param {(number|SignedTreeHead)} second - The second signed tree head or
   * its size.
   * @return {Promise.<Array<ArrayBuffer>>} A Promise than is resolved with an
   * array of ArrayBuffers containing the proofs.
   */
  getSTHConsistency(first, second) {
    let firstSize, secondSize;

    if(first instanceof SignedTreeHead) {
      firstSize = first.treeSize;
    } else if(typeof first === 'number') {
      firstSize = first;
    } else {
      return Promise.reject(new Error('Unknown first head type'));
    }

    if(second instanceof SignedTreeHead) {
      secondSize = second.treeSize;
    } else if(typeof second === 'number') {
      secondSize = second;
    } else {
      return Promise.reject(new Error('Unknown second head type'));
    }

    const params = {
      first: firstSize,
      second: secondSize
    };

    const url = this.getBaseUrl() + '/get-sth-consistency?' +
      paramsToQueryString(params);

    let sequence = getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const cons = [];

      for(let proof of res.consistency)
        cons.push(pvutils.stringToArrayBuffer(pvutils.fromBase64(proof)));

      return cons;
    });

    return sequence;
  }

  /**
   * Get merkle audit proof by leaf hash.
   * @param {(number|SignedTreeHead)} sth - The signed tree head or the tree
   * size on which to base the proof.
   * @param {ArrayBuffer} hash - The leaf hash.
   * @return {Promise.<AuditProof>} A promise that is resolved with the audit
   * proof.
   */
  getProofByHash(sth, hash) {
    let treeSize;

    if(sth instanceof SignedTreeHead) {
      treeSize = sth.treeSize;
    } else if(typeof sth === 'number') {
      treeSize = sth;
    } else {
      return Promise.reject(new Error('Unknown signed tree head type'));
    }

    const params = {
      tree_size: treeSize,
      hash: pvutils.toBase64(pvutils.arrayBufferToString(hash))
    };

    const url = this.getBaseUrl() + '/get-proof-by-hash?' +
      paramsToQueryString(params);

    let sequence = getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const auditPath = [];
      res.audit_path.forEach(p => {
        auditPath.push(pvutils.stringToArrayBuffer(pvutils.fromBase64(p)));
      });
      return {
        index: res.leaf_index,
        auditPath
      };
    });

    return sequence;
  }

  /**
   * Get merkle audit proof by leaf hash.
   * @param {(number|SignedTreeHead)} sth - The signed tree head or the tree
   * size on which to base the proof.
   * @param {MerkleTreeLeaf} leaf - The merkle tree leaf.
   * @return {Promise.<AuditProof>} A promise that is resolved with the audit
   * proof.
   */
  getProofByLeaf(sth, leaf) {
    return leaf.getHash().then(h => this.getProofByHash(sth, h));
  }

  /**
   * Get entries from the log.
   * @param {number} start - The index of the first entry.
   * @param {number} end - The index of the last entry.
   * @return {Promise.<Array<LogEntry>>} A promise that is resolved with an
   * array of MerkleTreeLeaf structures.
   */
  getEntries(start, end) {
    const params = {
      start,
      end
    };

    const url = this.getBaseUrl() + '/get-entries?' +
      paramsToQueryString(params);

    let sequence = getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const entries = [];

      res.entries.forEach(entry => {
        const leafData = pvutils.stringToArrayBuffer(pvutils.fromBase64(
          entry.leaf_input));
        const leaf = MerkleTreeLeaf.fromBinary(leafData);
        let extraData;
        if(leaf.timestampedEntry.type === LogEntryType.x509_entry)
          extraData = parseCertExtraData(pvutils.stringToArrayBuffer(
            pvutils.fromBase64(entry.extra_data)));
        else
          extraData = parsePrecertExtraData(pvutils.stringToArrayBuffer(
            pvutils.fromBase64(entry.extra_data)));

        entries.push({
          leaf,
          extraData
        });
      });

      return entries;
    });

    return sequence;
  }

  /**
   * Get accepted roots.
   * @return {Promise.<Array<pkijs.Certificate>>} An array of certificates.
   */
  getRoots() {
    let sequence = getFetch()(this.getBaseUrl() + '/get-roots');

    sequence = sequence.then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const certs = [];

      res.certificates.forEach(cert => {
        const certData = pvutils.stringToArrayBuffer(pvutils.fromBase64(cert));
        const asn1 = asn1js.fromBER(certData);
        certs.push(new pkijs.Certificate({ schema: asn1.result }));
      });

      return certs;
    });

    return sequence;
  }

  /**
   * Get an entry from the log and the audit path.
   * @param {(number|SignedTreeHead)} sth - The signed tree head or the tree
   * size on which to base the proof.
   * @param {number} index - The index of the entry.
   * @return {Promise.<LogEntryAndProof>} The log entry with the audit path.
   */
  getEntryAndProof(sth, index) {
    let treeSize;

    if(sth instanceof SignedTreeHead) {
      treeSize = sth.treeSize;
    } else if(typeof sth === 'number') {
      treeSize = sth;
    } else {
      return Promise.reject(new Error('Unknown signed tree head type'));
    }

    const params = {
      leaf_index: index,
      tree_size: treeSize
    };

    const url = this.getBaseUrl() + '/get-entry-and-proof?' +
      paramsToQueryString(params);

    let sequence = getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const leafData = pvutils.stringToArrayBuffer(pvutils.fromBase64(
        res.leaf_input));
      const leaf = MerkleTreeLeaf.fromBinary(leafData);
      let extraData;
      if(leaf.timestampedEntry.type === LogEntryType.x509_entry)
        extraData = parseCertExtraData(pvutils.stringToArrayBuffer(
          pvutils.fromBase64(res.extra_data)));
      else
        extraData = parsePrecertExtraData(pvutils.stringToArrayBuffer(
          pvutils.fromBase64(res.extra_data)));
      const auditPath = [];

      res.audit_path.forEach(p => {
        auditPath.push(pvutils.stringToArrayBuffer(pvutils.fromBase64(p)));
      });

      return {
        leaf,
        extraData,
        auditPath
      };
    });

    return sequence;
  }
}
