/**
 * Certificate Transparency Utilities
 * CTMonitor class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import CompactMerkleTree from './CompactMerkleTree';

/**
 * A callback that is provided with the results of a verification.
 * @callback sthVerificationCallback
 * @param {Boolean} The result of the verification.
 * @param {SignedTreeHead} The first STH used for the verification.
 * @param {SignedTreeHead} The second STH used for the verification.
 */

/**
 * A callback that is provided with a series of certificates.
 * @callback certsCallback
 * @param {Array.<LogEntry>} The certificates.
 */

/**
 * Return the value of a parameter or the default value if one has not been
 * specified.
 * @param {Array} opts - An array with all parameters.
 * @param {string} key - The parameter needed.
 * @return The value of the parameter.
 */
function getParameter(opts, key) {
  if(key in opts)
    return opts[key];

  switch(key) {
    case 'timerInterval':
      return 10000;
    case 'verifySTHConsistency':
      return false;
    case 'verifySTHConsistencyCallback':
      return (result, oldSTH, newSTH) => {};
    case 'fetchNewCertificates':
      return false;
    case 'fetchNewCertificatesCallback':
      return (certs) => {};
    case 'verifyTree':
      return false;
    case 'verifyTreeCallback':
      return (result, oldSTH, newSTH) => {};
    default:
      return null;
  }
};

/**
 * CTMonitor class
 */
export default class CTMonitor {
  /**
   * Construct a CTMonitor.
   * @param {CTLog} log - The log to be monitored.
   * @param {Array} opts - The options for the monitor. Please see the members
   * of this class to find the various options.
   */
  constructor(log, opts = {}) {
    /**
     * @type {CTLog}
     * @description The log.
     */
    this.log = log;
    /**
     * @type {SignedTreeHead}
     * @description The previous STH.
     */
    this.previousSTH = null;
    /**
     * @type {number}
     * @description The timer used to check for a new STH.
     */
    this.timer = null;
    /**
     * @type {number}
     * @description The interval between checking for a new STH.
     */
    this.timerInterval = getParameter(opts, 'timerInterval');
    /**
     * @type {Boolean}
     * @description Verify the consistency of the new STH.
     */
    this.verifySTHConsistency = getParameter(opts, 'verifySTHConsistency');
    /**
     * @type {sthVerificationCallback}
     * @description Verification consistency callback.
     */
    this.verifySTHConsistencyCallback = getParameter(opts,
      'verifySTHConsistencyCallback');
    /**
     * @type {Boolean}
     * @description Fetch new certificates.
     */
    this.fetchNewCertificates = getParameter(opts, 'fetchNewCertificates');
    /**
     * @type {certsCallback}
     * @description Certificates fetching callback.
     */
    this.fetchNewCertificatesCallback = getParameter(opts,
      'fetchNewCertificatesCallback');
    /**
     * @type {Boolean}
     * @description Verify the new tree. In effect, this verifies that the new
     * entries with the old STH generate the new STH. If this is set to true,
     * then verifySTHConsistency need not be set since it is tested here too.
     */
    this.verifyTree = getParameter(opts, 'verifyTree');
    /**
     * @type {sthVerificationCallback}
     * @description Tree verification callback.
     */
    this.verifyTreeCallback = getParameter(opts, 'verifyTreeCallback');
  }

  /**
   * Start monitoring.
   */
  start() {
    this.log.getSTH().then(sth => {
      this.previousSTH = sth;
      this.timer = setInterval(this.monitorChange.bind(this), this.timerInterval);
    });
  }

  /**
   * Stop monitoring
   */
  stop() {
    clearInterval(this.timer);
  }

  /**
   * Monitor for any changes.
   */
  async monitorChange() {
    const newSTH = await this.log.getSTH();

    if(this.previousSTH.treeSize === newSTH.treeSize)
      return;

    if(this.verifySTHConsistency) {
      const proofs = await this.log.getSTHConsistency(this.previousSTH,
        newSTH);
      const result = await this.previousSTH.verifyConsistency(newSTH, proofs);
      this.verifySTHConsistencyCallback(result, this.previousSTH, newSTH);
    }

    let certs = [];
    if(this.fetchNewCertificates || this.verify) {
      let start = this.previousSTH.treeSize;
      let end = newSTH.treeSize - 1;
      let left = end - start + 1

      while(left > 0) {
        const newCerts = await this.log.getEntries(end - left + 1, end);
        certs = certs.concat(newCerts);
        left -= newCerts.length;
      }
    }

    if(this.fetchNewCertificates)
      this.fetchNewCertificatesCallback(certs);

    if(this.verifyTree) {
      const lastEntryAndProof = await this.log.getEntryAndProof(
        this.previousSTH, this.previousSTH.treeSize - 1);
      const auditPath = lastEntryAndProof.auditPath;
      const node = lastEntryAndProof.leaf;

      const cmt = new CompactMerkleTree();

      let res = await cmt.init(this.previousSTH.rootHash, auditPath, node,
        this.previousSTH.treeSize);

      if(res === false) {
        this.verifyTreeCallback(false, this.previousSTH, newSTH);
      } else {
        for(let i = 0; i < certs.length; i++)
          await cmt.addLeaf(certs[i].leaf);

        const verifyRoot = await cmt.calculateRoot();
        const newRootView = new Uint8Array(newSTH.rootHash);
        const verifyRootView = new Uint8Array(verifyRoot);

        if(newRootView.length !== verifyRootView.length) {
          this.verifyTreeCallback(false, this.previousSTH, newSTH);
        } else {
          let idx = 0;
          for(idx = 0; idx < newRootView.length; idx++) {
            if(newRootView[idx] !== verifyRootView[idx]) {
              this.verifyTreeCallback(false, this.previousSTH, newSTH);
              break;
            }
          }
          if(idx === newRootView.length)
            this.verifyTreeCallback(true, this.previousSTH, newSTH);
        }
      }
    }

    this.previousSTH = newSTH;
  }

  /**
   * Verify the whole tree of a log.
   * Warning: this will download all entries from the log, and thus can
   * generate a lot of traffic.
   * @param {CTLog} log - The CT log.
   * @param {Promise.<Boolean>} A Promise that resolves with the result of the
   * validation.
   */
  static async verifyFullTree(log) {
    const sth = await log.getSTH();

    /**
     * There is no need to initialize the CMT with init() since there are no
     * nodes in the actual tree at this time.
     */
    const cmt = new CompactMerkleTree();

    let start = 0;
    let end = sth.treeSize - 1;
    let left = sth.treeSize;

    while(left > 0) {
      const newCerts = await log.getEntries(end - left + 1, end);

      for(let i = 0; i < newCerts.length; i++) {
        let res = await cmt.addLeaf(newCerts[i].leaf);

        if(res === false)
          return false;
      }

      left -= newCerts.length;
    }

    const rootView = new Uint8Array(sth.rootHash);
    const verifyRoot = await cmt.calculateRoot();
    const verifyRootView = new Uint8Array(verifyRoot);

    if(rootView.length !== verifyRootView.length)
      return false;

    for(let i = 0; i < rootView.length; i++)
      if(rootView[i] !== verifyRootView[i])
        return false;

    return true;
  }
}
