/**
 * Certificate Transparency Utilities
 * CompactMerkleTree class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import * as pkijs from 'pkijs';

/**
 * CompactMerkleTree class
 * In this specific case, all nodes are considered as hashes.
 */
export default class CompactMerkleTree {
  /**
   * Construct a CompactMerkleTree.
   * This is used for validating trees.
   */
  constructor() {
    /**
     * @type {Array.<ArrayBuffer>}
     * @description The nodes in the CMT.
     */
    this.nodes = [];
    /**
     * @type {number}
     * @description The size of the full tree this CMT corresponds to.
     */
    this.size = 0;
    /**
     * @type {number}
     * @description The levels of the tree.
     */
    this.levels = 0;
  }

  /**
   * Initialize the tree.
   * You can get the leftNodes and the rightNode by getting the entry and proof
   * for the last node when getting a Signed Tree Head. If there are any nodes,
   * they are removed.
   * @param {ArrayBuffer} root - The root.
   * @param {Array.<ArrayBuffer>} leftNodes - The left side nodes of the tree.
   * @param {ArrayBuffer} rightNode - The rightmost node of the tree.
   * @param {number} size - The size of the full tree this CMT corresponds to.
   * @return {Promise.<Boolean>} - A Promise that resolves with the result of
   * the initialization. Errors will be thrown as exceptions, so for the moment
   * this just returns the result of the validation of the root.
   */
  async init(root, leftNodes, rightNode, size) {
    this.nodes = [];
    this.size = size;
    if(this.size === 0) {
      this.levels = 0;
      return;
    }
    this.levels = Math.ceil(Math.log2(size));

    let level = 0;
    let it = 0;
    let prevSize = size - 1;
    for(; prevSize !== 0; prevSize >>= 1) {
      if((prevSize & 1) !== 0) {
        this.nodes[level] = leftNodes[it];
        it++;
      }
      level++;
    }

    if(it !== leftNodes.length)
      throw new Error('Invalid number of leftNodes');

    const rightNodeHash = await rightNode.getHash();
    await this.pushBack(rightNodeHash, 0);
    const verifyRoot = await this.calculateRoot();

    const rootView = new Uint8Array(root);
    const verifyRootView = new Uint8Array(verifyRoot);

    if(rootView.length !== verifyRootView.length)
      return false;

    for(let i = 0; i < rootView.length; i++) {
      if(rootView[i] !== verifyRootView[i])
        return false;
    }

    return true;
  }

  /**
   * Get the hash of two nodes.
   * @param {ArrayBuffer} node1 - The first node.
   * @param {ArrayBuffer} node2 - The second node.
   * @return {Promise.<ArrayBuffer>} A promise that is resolved with the hash.
   */
  hashNodes(node1, node2) {
    const node1View = new Uint8Array(node1);
    const node2View = new Uint8Array(node2);
    const data = new ArrayBuffer(1 + node1View.length + node2View.length);
    const dataView = new Uint8Array(data);
    const webcrypto = pkijs.getEngine();

    dataView[0] = 0x01;
    dataView.set(node1View, 1);
    dataView.set(node2View, 1 + node1View.length);

    return webcrypto.subtle.digest({ name: 'SHA-256' }, data);
  }

  /**
   * Push a node at a specific level.
   * @param {ArrayBuffer} node - The node to push. This has to be a hash.
   * @param {number} level - The level where to push it at.
   * @return {Promise.<Boolean>} A promise that is resolved with the result of
   * the operation. This is always true, but it is used since if we need to hash
   * something, we have an asynchronous operation.
   */
  pushBack(node, level) {
    if(this.nodes.length <= level) {
      this.nodes.push(node);
      return Promise.resolve(true);
    } else if(typeof this.nodes[level] === 'undefined') {
      this.nodes[level] = node;
      return Promise.resolve(true);
    } else {
      return this.hashNodes(this.nodes[level], node).then(hash =>
        this.pushBack(hash, level + 1)
      ).then(res => {
        if(res === true)
          delete this.nodes[level];
        return res;
      })
    }
  }

  /**
   * Add a new leaf.
   * @param {MerkleTreeLeaf} leaf - The leaf to add.
   * @return {Promise.<Boolean>} A promise that is resolved with the result of
   * the operation. This is always true, but it is used since if we need to hash
   * something, we have an asynchronous operation.
   */
  async addLeaf(leaf) {
    const leafHash = await leaf.getHash();

    return this.pushBack(leafHash, 0).then(result => {
      if(result) {
        this.size++;
        /**
         * If this.size - 1 is a power of 2, then this means we added a new
         * level.
         */
        if(((this.size - 1) & (this.size - 2)) === 0)
          this.levels++;
      }

      return result;
    });
  }

  /**
   * Calculate the current root.
   * @return {Promise.<ArrayBuffer>} A promise that is resolved with the current
   * root hash.
   */
  async calculateRoot() {
    let rightSibling = null;

    for(let level = 0; level < this.levels; level++) {
      if(typeof this.nodes[level] !== 'undefined') {
        if(rightSibling == null)
          rightSibling = this.nodes[level];
        else
          rightSibling = await this.hashNodes(this.nodes[level], rightSibling);
      }
    }

    return rightSibling;
  }
}
