import * as CTUtils from '../../../';
import * as pvutils from 'pvutils';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

const typemap = {
  '2.5.4.6': 'countryName',
  '2.5.4.11': 'organizationalUnitName',
  '2.5.4.10': 'organizationName',
  '2.5.4.3': 'commonName',
  '2.5.4.7': 'localityName',
  '2.5.4.8': 'stateOrProvinceName',
  '2.5.4.12': 'title',
  '2.5.4.42': 'givenName',
  '2.5.4.43': 'initials',
  '2.5.4.4': 'surname',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '2.5.4.15': 'businessCategory',
  '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionLocalityName',
  '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionStateOrProvinceName',
  '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionCountryName',
  '2.5.4.5': 'serialNumber',
  '2.5.4.9': 'streetAddress',
  '2.5.4.17': 'postalCode',
  '2.5.4.45': 'uniqueIdentifier'
};

function rdnToText(rdn) {
  let subj = '';

  for(let i = 0; i < rdn.typesAndValues.length; i++) {
    let tv = rdn.typesAndValues[i];
    let type = typemap[tv.type];

    if(typeof type === 'undefined')
      type = tv.type;

    subj += (type + '=' + tv.value.valueBlock.value);
    if(i !== (rdn.typesAndValues.length - 1))
      subj += ', ';
  }

  return subj;
}

function certToPEM(cert) {
  let b64 = pvutils.toBase64(pvutils.arrayBufferToString(
    cert.toSchema().toBER(false)));

  let pem = '-----BEGIN CERTIFICATE-----\n';
  while(b64.length > 64) {
    pem += b64.substr(0, 64);
    pem += '\n';
    b64 = b64.substr(64);
  }
  pem += b64;
  pem += '\n-----END CERTIFICATE-----\n';

  return pem;
}

export function getLogs() {
  const logHelper = new CTUtils.CTLogHelper();
  return logHelper.fetch(CTUtils.CTLogHelper.lists.google).then(res => {
    return logHelper.generateIds();
  }).then(res => {
    let logs = [];

    logHelper.logs.forEach(log => {
      logs.push({
        url: log.url,
        pubkey: pvutils.toBase64(pvutils.arrayBufferToString(log.pubKey)),
        version: log.version,
        logid: pvutils.toBase64(pvutils.arrayBufferToString(log.logId)),
        description: log.description,
        operators: log.operators.join(', ')
      });
    });

    return logs;
  });
}

export function getMonitor(opts) {
  const log = new CTUtils.CTLog(opts.url, pvutils.stringToArrayBuffer(
    pvutils.fromBase64(opts.pubkey)), opts.version, pvutils.stringToArrayBuffer(
    pvutils.fromBase64(opts.logid)), 0, opts.description);

  const monitor = new CTUtils.CTMonitor(log, {
    timerInterval: opts.update * 1000,
    fetchNewCertificates: true,
    fetchNewCertificatesCallback: entries => {
      let certs = [];

      entries.forEach(entry => {
        const leaf = entry.leaf;
        const timestampedEntry = leaf.timestampedEntry;
        let cert;

        if(timestampedEntry.type === CTUtils.LogEntryType.x509_entry) {
          const asn1 = asn1js.fromBER(timestampedEntry.cert);
          cert = new pkijs.Certificate({schema: asn1.result});
        } else {
          cert = entry.extraData[0];
        }

        certs.push({
          subject: rdnToText(cert.subject),
          pem: certToPEM(cert),
          filename: entry.index.toString() + '.pem'
        });
      });

      opts.callback(certs);
    }
  });

  return monitor;
}
