/**
 * Certificate Transparency Utilities
 * MerkleTreeLeaf class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import * as pkijs from 'pkijs';
import TimestampedEntry from './TimestampedEntry';

/**
 * MerkleTreeLeaf class
 */
export default class MerkleTreeLeaf {
  /**
   * Construct a TimestampedEntry.
   * @param {number} version - The version.
   * @param {number} type - The type of the leaf.
   * @param {TimestampedEntry} timestampedEntry - The TimestampedEntry.
   */
  constructor(version, type, timestampedEntry) {
    /**
     * @type number
     * @description The version.
     */
    this.version = version;
    /**
     * @type number
     * @description The type of the leaf.
     */
    this.type = type;
    /**
     * @type TimestampedEntry
     * @description The TimestampedEntry.
     */
    this.timestampedEntry = timestampedEntry;
  }

  /**
   * Encode the leaf and get the binary representation.
   * @return {ArrayBuffer} An ArrayBuffer containing the binary representation
   * of the leaf.
   */
  toBinary() {
    const timestampedEntryBuf = this.timestampedEntry.toBinary();
    const timestampedEntryView = new Uint8Array(timestampedEntryBuf);
    const merkleTreeLeaf = new ArrayBuffer(2 + timestampedEntryView.length);
    const merkleTreeLeafView = new Uint8Array(merkleTreeLeaf);

    merkleTreeLeafView[0] = this.version;

    merkleTreeLeafView[1] = this.type;

    merkleTreeLeafView.set(timestampedEntryView, 2);

    return merkleTreeLeaf;
  }

  /**
   * Parse a binary MerkleTreeLeaf and return a new object.
   * @param {ArrayBuffer} merkleTreeLeafBin - The binary MerkleTreeLeaf.
   * @return {MerkleTreeLeaf} The MerkleTreeLeaf object.
   */
  static fromBinary(merkleTreeLeafBin) {
    const merkleTreeLeafBinView = new Uint8Array(merkleTreeLeafBin);

    const version = merkleTreeLeafBinView[0];

    const type = merkleTreeLeafBinView[1];

    const timestampedEntryBuf = merkleTreeLeafBinView.slice(2).buffer;

    const timestampedEntry = TimestampedEntry.fromBinary(timestampedEntryBuf);

    return new MerkleTreeLeaf(version, type, timestampedEntry);
  }

  /**
   * Get the hash of the leaf.
   * Per section 2.1 of RFC6962 to generate the hash of a leaf, a \x00 needs to
   * be prepended.
   * @return {Promise<ArrayBuffer>} A Promise that is resolved with the hash of
   * the leaf.
   */
  getHash() {
    const webcrypto = pkijs.getEngine();
    const merkleTreeLeafView = new Uint8Array(this.toBinary());
    const toHash = new ArrayBuffer(merkleTreeLeafView.length + 1);
    const toHashView = new Uint8Array(toHash);

    toHashView[0] = 0;
    toHashView.set(merkleTreeLeafView, 1);

    return webcrypto.subtle.digest({ name: 'SHA-256' }, toHash);
  }

  /**
   * Verify the inclusion of a leaf by hash.
   * This is a static function, so it can be used directly if there are no
   * details for the leaf other than its hash.
   * @param {SignedTreeHead} sth - The SignedTreeHead against which the check
   * will be made.
   * @param {number} index - The index of the leaf in the tree.
   * @param {Array<ArrayBuffer>} auditPath - The audit path.
   * @param {ArrayBuffer} hash - The hash of the leaf.
   * @return {Promise<Boolean>} A promise that is resolved with the result
   * of the inclusion verification.
   */
  static verifyInclusionByHash(sth, index, auditPath, hash) {
    if(index > sth.treeSize)
      return Promise.reject(new Error('Index is greater than tree size'));

    /* Calculate the expected size of the audit path */
    let length = 0;
    let lastNode = sth.treeSize - 1;
    let tmpIndex = index;
    while(lastNode > 0) {
      if(((tmpIndex % 2) > 0) || (tmpIndex < lastNode))
        length++;
      tmpIndex = Math.floor(tmpIndex / 2);
      lastNode = Math.floor(lastNode / 2);
    }

    if(auditPath.length !== length)
      return Promise.reject(new Error('Audit path size wrong'));

    /* Start verification */

    let sequence = Promise.resolve(hash);
    lastNode = sth.treeSize - 1;

    const auditPathArray = auditPath.slice();

    /* The whole sequence is resolved by the latest calculated hash */
    while(lastNode > 0) {
      if((index % 2) > 0) {
        sequence = sequence.then(h => {
          const hashView = new Uint8Array(h);
          const nodeView = new Uint8Array(auditPathArray.shift());

          const data = new ArrayBuffer(hashView.length + nodeView.length + 1);
          const dataView = new Uint8Array(data);

          const webcrypto = pkijs.getEngine();

          dataView[0] = 0x01;
          dataView.set(nodeView, 1);
          dataView.set(hashView, 1 + nodeView.length);

          return webcrypto.subtle.digest({ name: 'SHA-256' }, data);
        });
      } else {
        sequence = sequence.then(h => {
          const hashView = new Uint8Array(h);
          const nodeView = new Uint8Array(auditPathArray.shift());

          const data = new ArrayBuffer(hashView.length + nodeView.length + 1);
          const dataView = new Uint8Array(data);

          const webcrypto = pkijs.getEngine();

          dataView[0] = 0x01;
          dataView.set(hashView, 1);
          dataView.set(nodeView, 1 + hashView.length);

          return webcrypto.subtle.digest({ name: 'SHA-256' }, data);
        });
      }

      index = Math.floor(index / 2);
      lastNode = Math.floor(lastNode / 2);
    }

    /* Finally compare the calculated root hash against the actual one */
    sequence = sequence.then(h => {
      const hashView = new Uint8Array(h);
      const rootView = new Uint8Array(sth.rootHash);

      if(hashView.length !== rootView.length)
        return false;

      for(let i = 0; i < hashView.length; i++)
        if(hashView[i] !== rootView[i])
          return false;

      return true;
    });

    return sequence;
  }

  /**
   * Verify the inclusion of this leaf in a log.
   * @param {SignedTreeHead} sth - The SignedTreeHead against which the check
   * will be made.
   * @param {number} index - The index of the leaf in the tree.
   * @param {Array<ArrayBuffer>} auditPath - The audit path.
   * @return {Promise<Boolean>} A promise that is resolved with the result
   * of the inclusion verification.
   */
  verifyInclusion(sth, index, auditPath) {
    return this.getHash().then(h =>
      MerkleTreeLeaf.verifyInclusionByHash(sth, index, auditPath, h)
    );
  }
}
