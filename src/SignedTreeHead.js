/**
 * Certificate Transparency Utilities
 * SignedTreeHead class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { SignatureType } from './Enums';
import { uint64ToArrayBuffer } from './Common';

/**
 * SignedTreeHead class
 */
export default class SignedTreeHead {
  /**
   * Construct a SignedTreeHead.
   * @param {number} treeSize - The size of the tree.
   * @param {number} timestamp - The timestamp.
   * @param {ArrayBuffer} rootHash - The Merkle Tree Hash.
   * @param {ArrayBuffer} signature - The signature.
   * @param {number} version - The version.
   */
  constructor(treeSize, timestamp, rootHash, signature, version) {
    /**
     * @type {number}
     * @description The size of the tree.
     */
    this.treeSize = treeSize;
    /**
     * @type {number}
     * @description The timestamp.
     */
    this.timestamp = timestamp;
    /**
     * @type {ArrayBuffer}
     * @description The Merkle Tree Hash.
     */
    this.rootHash = rootHash;
    /**
     * @type {ArrayBuffer}
     * @description The signature.
     */
    this.signature = signature;
    /**
     * @type {number}
     * @description The version.
     */
    this.version = version;
  }

  /**
   * Verify the signature of an SignedTreeHead.
   * @param {ArrayBuffer} pubKey - The public key of the log.
   * @return {Promise<Boolean>} A promise that is resolved with the result
   * of the verification.
   */
  verify(pubKey) {
    let sequence = Promise.resolve();
    const signatureView = new Uint8Array(this.signature);

    const dataStruct = new ArrayBuffer(50);
    const dataStructView = new Uint8Array(dataStruct);

    /*
     * Prepare the struct with the data that was signed.
     */
    dataStructView[0] = this.version;

    dataStructView[1] = SignatureType.tree_hash;

    dataStructView.set(new Uint8Array(uint64ToArrayBuffer(this.timestamp)), 2);

    dataStructView.set(new Uint8Array(uint64ToArrayBuffer(this.treeSize)), 10);

    dataStructView.set(new Uint8Array(this.rootHash), 18);

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
   * Verify consistency between two Signed Tree Heads.
   * @param {SignedTreeHead} second - The second SignedTreeHead.
   * @param {Array<ArrayBuffer>} proofs - The consistency proofs.
   * @return {Promise<Boolean>} A promise that is resolved with the
   * result of the consistency verification.
   */
  verifyConsistency(second, proofs) {
    /**
     * Both functions return an array whose first item is the old hash
     * and the second item is the new hash. This helps in creating
     * the chain during the verification.
     */
    const hashRightChild = async (oldHash, newHash, node) => {
      const oldHashView = new Uint8Array(oldHash);
      const newHashView = new Uint8Array(newHash);
      const nodeView = new Uint8Array(node);

      const data = new ArrayBuffer(oldHashView.length + nodeView.length + 1);
      const dataView = new Uint8Array(data);

      const webcrypto = pkijs.getEngine();

      dataView[0] = 0x01;
      dataView.set(nodeView, 1);
      dataView.set(oldHashView, 1 + nodeView.length);

      oldHash = await webcrypto.subtle.digest({ name: 'SHA-256' }, data);

      dataView.set(newHashView, 1 + nodeView.length);

      newHash = await webcrypto.subtle.digest({ name: 'SHA-256' }, data);

      return [ oldHash, newHash ];
    };
    const hashLeftChild = async (oldHash, newHash, node) => {
      const newHashView = new Uint8Array(newHash);
      const nodeView = new Uint8Array(node);

      const data = new ArrayBuffer(newHashView.length + nodeView.length + 1);
      const dataView = new Uint8Array(data);

      const webcrypto = pkijs.getEngine();

      dataView[0] = 0x01;
      dataView.set(newHashView, 1);
      dataView.set(nodeView, 1 + newHashView.length);

      newHash = await webcrypto.subtle.digest({ name: 'SHA-256' }, data);

      return [ oldHash, newHash ];
    };

    if(second.treeSize < this.treeSize)
      return Promise.reject(new Error('Second tree is smaller than first'));

    if(second.timestamp < this.timestamp)
      return Promise.reject(new Error('Second timestamp is less than first'));

    /**
     * If the first tree is empty or has the same number of elements with the
     * second we assume it's valid.
     */
    if(this.treeSize === 0)
      return Promise.resolve(true);

    if(this.treeSize === second.treeSize) {
      const firstRootHashView = new Uint8Array(this.rootHash);
      const secondRootHashView = new Uint8Array(second.rootHash);

      if(firstRootHashView.length !== secondRootHashView.length)
        return Promise.resolve(false);

      for(let i = 0; i < firstRootHashView; i++)
        if(firstRootHashView[i] !== secondRootHashView[i])
          return Promise.resolve(false);

      return Promise.resolve(true);
    }

    /* Calculate the expected size of the proof */
    let length = 0;
    let b = 0;
    let m = this.treeSize;
    let n = second.treeSize;

    while(m !== n) {
      length++;

      const k = 2 ** Math.floor(Math.log2(n - 1));

      if(m <= k) {
        n = k;
      } else {
        m -= k;
        n -= k;
        b = 1;
      }
    }

    length += b;

    if(proofs.length !== length)
      return Promise.reject(new Error('Proof size wrong'));

    /* Start verification */

    let node = this.treeSize - 1;
    let lastNode = second.treeSize - 1;

    while((node % 2) > 0) {
      node = Math.floor(node / 2);
      lastNode = Math.floor(lastNode / 2);
    }

    const proofArray = proofs.slice();

    let sequence;
    /**
     * Sequence is resolved with old hash and new hash in order to be ready
     * for input to the chain of calls below.
     */
    if(node > 0) {
      const h = proofArray.shift();
      sequence = Promise.resolve([h, h]);
    } else {
      sequence = Promise.resolve([this.rootHash, this.rootHash]);
    }

    /**
     * The following chain of calls to hashRightChild and hashLeftChild works
     * because both callbacks for success expect an array with the old hash
     * and the new one, and return such an array.
     */
    while(node > 0) {
      if((node % 2) > 0) {
        sequence = sequence.then((args) => {
          const oldHash = args[0];
          const newHash = args[1];
          return hashRightChild(oldHash, newHash, proofArray.shift())
        });
      } else if(node < lastNode) {
        sequence = sequence.then((args) => {
          const oldHash = args[0];
          const newHash = args[1];
          return hashLeftChild(oldHash, newHash, proofArray.shift())
        });
      }

      node = Math.floor(node / 2);
      lastNode = Math.floor(lastNode / 2);
    }

    while(lastNode > 0) {
      sequence = sequence.then((args) => {
        const oldHash = args[0];
        const newHash = args[1];
        return hashLeftChild(oldHash, newHash, proofArray.shift())
      });
      lastNode = Math.floor(lastNode / 2);
    }

    /* Finally compare calculated root hashes against the actual ones */
    sequence = sequence.then((args) => {
      const oldHash = args[0];
      const newHash = args[1];
      const oldHashView = new Uint8Array(oldHash);
      const newHashView = new Uint8Array(newHash);
      const oldRootView = new Uint8Array(this.rootHash);
      const newRootView = new Uint8Array(second.rootHash);

      if((oldHashView.length !== oldRootView.length) ||
        (newHashView.length !== newRootView.length))
        return false;

      for(let i = 0; i < oldHashView.length; i++)
        if(oldHashView[i] !== oldRootView[i])
          return false;

      for(let i = 0; i < newHashView.length; i++)
        if(newHashView[i] !== newRootView[i])
          return false;

      return true;
    });

    return sequence;
  }
}
