/**
 * Certificate Transparency Utilities
 * Various enums
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * Version
 */
export const Version = Object.freeze({
  v1: 0
});

/**
 * Entry type
 */
export const LogEntryType = Object.freeze({
  x509_entry: 0,
  precert_entry: 1
});

/**
 * Leaf type at Merkle Tree
 */
export const MerkleLeafType = Object.freeze({
  timestamped_entry: 0
});

/**
 * Signature type
 */
export const SignatureType = Object.freeze({
  certificate_timestamp: 0,
  tree_hash: 1
});
