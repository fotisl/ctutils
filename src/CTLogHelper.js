/**
 * Certificate Transparency Utilities
 * CTLogHelper class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import * as pvutils from 'pvutils';
import CTLog from './CTLog';
import { Version } from './Enums';
import { getFetch } from './Engines';

/**
 * CTLogHelper class
 */
export default class CTLogHelper {
  /**
   * Construct a CTLog helper object.
   */
  constructor(logs = []) {
    /**
     * @type Array.<CTLog>
     * @description An array of all logs stored.
     */
    this.logs = logs;
  }

  /**
   * Fetch all logs from a url based on the standard google json schema.
   * @param {string} url - The url to fetch logs from.
   * @return {Promise.<Boolean>} A Promise that is resolved with the result of
   * the file parsing.
   */
  fetch(url) {
    return getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    }).then(res => {
      let ret = true;
      let operatorList = {};

      if(!('operators' in res) || !('logs' in res))
        return false;

      res.operators.forEach(operator => {
        if(!('id' in operator) || !('name' in operator)) {
          ret = false;
          return;
        }
        operatorList[operator['id']] = operator['name'];
      });

      if(!ret)
        return ret;

      let logs = [];
      res.logs.forEach(log => {
        if(!('url' in log) || !('key' in log) ||
          !('description' in log) || !('operated_by' in log) ||
          !('maximum_merge_delay' in log)) {
          ret = false;
          return;
        }

        const pubKey = pvutils.stringToArrayBuffer(pvutils.fromBase64(log.key));
        let logId = null;
        if('log_id' in log)
          logId = pvutils.stringToArrayBuffer(pvutils.fromBase64(log.log_id));

        let operators = [];
        log.operated_by.forEach(operator => {
          operators.push(operatorList[operator]);
        });

        logs.push(new CTLog(log.url, pubKey, Version.v1, logId,
          log.maximum_merge_delay, log.description, operators));
      });

      if(ret)
        this.logs.push(...logs);

      return ret;
    });
  }

  /**
   * Find a log based on its id.
   * @param {ArrayBuffer} logId - The log's id.
   * @return {CTLog} The CT log or null if it cannot be found.
   */
  findById(logId) {
    const searchLogIdView = new Uint8Array(logId);

    for(const log of this.logs) {
      if(log.logId === null)
        continue;
      const logIdView = new Uint8Array(log.logId);

      let i;
      for(i = 0; i < logIdView.length; i++)
        if(logIdView[i] !== searchLogIdView[i]) {
          break;
        }

      if(i === logIdView.length)
        return log;
    }

    return null;
  }

  /**
   * Generate ids for all logs.
   * Since different logs may use different algorithms, the algorithm for
   * every log is heuristically determined. If you need to specify the
   * algorithm yourself, you can use the generateId() method of every CTLog.
   * @return {Promise.<Boolean>} The result of the generation. This will
   * normally be true, and it's used to notify that the calculation has
   * finished.
   */
  generateIds() {
    const generations = [];

    this.logs.forEach(log => {
      generations.push(log.generateId());
    });

    return Promise.all(generations).then(res => {
      let ret = true;

      res.forEach(r => {
        ret &= r;
      });

      return ret;
    });
  }

  /**
   * Find a log by url.
   * @param {string} url - The log's url.
   * @return {CTLog} The log or null if it cannot be found.
   */
  findByUrl(url) {
    let search = url;

    if(search.startsWith('https://'))
      search = search.substr(8);

    while(search.endsWith('/'))
      search = search.substr(0, search.length - 1);

    for(const log of this.logs) {
      let match = log.url;

      if(match.startsWith('https://'))
        match = match.substr(8);

      while(match.endsWith('/'))
        match = match.substr(0, match.length - 1);

      if(search === match)
        return log;
    };

    return null;
  }

  /**
   * Find a log by description.
   * The search is case insensitive and searches for if the string is part of
   * the log description. If multiple logs match the description, only the first
   * will be returned.
   * @param {string} description - The description that will be used for
   * matching.
   * @return {CTLog} The log or null if it cannot be found.
   */
  findByDescription(description) {
    for(const log of this.logs) {
      if(log.url.toLowerCase().includes(description.toLowerCase()))
        return log;
    };

    return null;
  }
}

CTLogHelper.lists = {
  googleCT: 'https://www.gstatic.com/ct/log_list/log_list.json',
  googleCTAll: 'https://www.gstatic.com/ct/log_list/all_logs_list.json',
  googleChromium: 'https://chromium.googlesource.com/chromium/src/+/master' +
    '/components/certificate_transparency/data/log_list.json?format=TEXT',
  apple: 'https://opensource.apple.com/source/security_certificates/security' +
    '_certificates-55093.40.3/certificate_transparency/log_list.json'
}
