/**
 * Certificate Transparency Utilities
 * TimestampedEntry class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

import { uint64ToArrayBuffer, arrayBufferToUint64 } from './Common';
import { LogEntryType } from './Enums';

/**
 * TimestampedEntry class
 */
export default class TimestampedEntry {
  /**
   * Construct a TimestampedEntry.
   * @param {number} timestamp - The timestamp of the entry.
   * @param {number} type - The type of the entry.
   * @param {ArrayBuffer} cert - The certificate or precertificate of the entry.
   * @param {ArrayBuffer} extensions - The extensions of the entry.
   */
  constructor(timestamp, type, cert, extensions) {
    /**
     * @type number
     * @description The timestamp of the entry.
     */
    this.timestamp = timestamp;
    /**
     * @type number
     * @description The type of the entry.
     */
    this.type = type;
    /**
     * @type ArrayBuffer
     * @description The certificate or precertificate of the entry.
     */
    this.cert = cert;
    /**
     * @type ArrayBuffer
     * @description The extensions of the entry.
     */
    this.extensions = extensions;
  }

  /**
   * Encode the entry and get the binary representation.
   * @return {ArrayBuffer} An ArrayBuffer containing the binary representation
   * of the entry.
   */
  toBinary() {
    let certView;
    let timestampedEntryLen;

    const extensionsView = new Uint8Array(this.extensions);

    certView = new Uint8Array(this.cert);
    if(this.type === LogEntryType.x509_entry)
      timestampedEntryLen = 15 + certView.length + extensionsView.length;
    else
      timestampedEntryLen = 12 + certView.length + extensionsView.length;

    const timestampedEntry = new ArrayBuffer(timestampedEntryLen);
    const timestampedEntryView = new Uint8Array(timestampedEntry);

    timestampedEntryView.set(new Uint8Array(uint64ToArrayBuffer(
      this.timestamp)));

    timestampedEntryView[8] = (this.type >> 8) & 0xff;
    timestampedEntryView[9] = this.type & 0xff;

    let offset = 10;

    if(this.type === LogEntryType.x509_entry) {
      timestampedEntryView[10] = (certView.length >> 16) & 0xff;
      timestampedEntryView[11] = (certView.length >> 8) & 0xff;
      timestampedEntryView[12] = certView.length & 0xff;
      offset += 3;
    }
    timestampedEntryView.set(certView, offset);

    timestampedEntryView[offset + certView.length] =
      (extensionsView.length >> 8) & 0xff;
    timestampedEntryView[offset + certView.length + 1] =
      extensionsView.length & 0xff;

    if(extensionsView.length > 0)
      timestampedEntryView.set(extensionsView, offset + 2 + certView.length);

    return timestampedEntry;
  }

  /**
   * Parse a binary TimestampedEntry and return a new object.
   * @param {ArrayBuffer} timestampedEntryBin - The binary TimestampedEntry.
   * @return {TimestampedEntry} The TimestampedEntry object.
   */
  static fromBinary(timestampedEntryBin) {
    const timestampedEntryBinView = new Uint8Array(timestampedEntryBin);

    const timestamp = arrayBufferToUint64(
      timestampedEntryBinView.slice(0, 8).buffer);

    const type = (timestampedEntryBinView[8] << 8) + timestampedEntryBinView[9];

    let cert, extensions;

    if(type === LogEntryType.x509_entry) {
      const certLen = (timestampedEntryBinView[10] << 16) +
        (timestampedEntryBinView[11] << 8) + timestampedEntryBinView[12];
      cert = timestampedEntryBinView.slice(13, 13 + certLen).buffer;
      extensions = timestampedEntryBinView.slice(13 + certLen).buffer;
    } else {
      let preCertLen = 32;
      preCertLen += (timestampedEntryBinView[42] << 16) +
        (timestampedEntryBinView[43] << 8) + timestampedEntryBinView[44];
      cert = timestampedEntryBinView.slice(10, 10 + preCertLen).buffer;
      extensions = timestampedEntryBinView.slice(10 + preCertLen).buffer;
    }

    return new TimestampedEntry(timestamp, type, cert, extensions);
  }
}
