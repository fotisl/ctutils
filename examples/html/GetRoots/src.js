import * as CTUtils from '../../../';
import * as pvutils from 'pvutils';

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
  return logHelper.fetch(CTUtils.CTLogHelper.lists.googleCT).then(res => {
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

export function getRoots(opts) {
  const log = new CTUtils.CTLog(opts.url, pvutils.stringToArrayBuffer(
    pvutils.fromBase64(opts.pubkey)), opts.version, pvutils.stringToArrayBuffer(
    pvutils.fromBase64(opts.logid)), 0, opts.description);

  return log.getRoots().then(roots => {
    let keyHashPromises = [];

    roots.forEach(root => {
      keyHashPromises.push(root.getKeyHash().then(hash => {
        return {
          filename: pvutils.bufferToHexCodes(hash) + '.pem',
          subject: rdnToText(root.subject),
          pem: certToPEM(root)
        };
      }));
    });

    return Promise.all(keyHashPromises);
  });
}
