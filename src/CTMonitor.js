/**
 * Certificate Transparency Utilities
 * CTMonitor class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

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
    }).catch(e => console.log(e));
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

    if(this.fetchNewCertificates) {
      let certs = [];

      let start = this.previousSTH.treeSize;
      let end = newSTH.treeSize - 1;
      let left = end - start + 1

      while(left > 0) {
        const newCerts = await this.log.getEntries(end - left + 1, end);
        certs = certs.concat(newCerts);
        left -= newCerts.length;
      }
      this.fetchNewCertificatesCallback(certs);
    }

    if(this.verifyTree) {
      /* TODO: implement tree checking */
    }

    this.previousSTH = newSTH;
  }
}