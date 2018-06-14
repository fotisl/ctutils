require('babel-polyfill');
const CTUtils = require('../..');
const pvutils = require('pvutils');
const fetch = require('node-fetch');
const WebCrypto = require('node-webcrypto-ossl');
const fs = require('fs');
const path = require('path');
const process = require('process');
const program = require('commander');

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

program
  .version('1.0.0')
  .description('Get roots accepted by a log')
  .option('-l, --list', 'List all logs', false)
  .option('-d, --description <text>',
    'Description of the log that will be used')
  .option('-i, --id <id>', 'Id of the log that will be used')
  .option('-u, --url <url>', 'URL of the log that will be used')
  .option('-o, --output <directory>', 'Save roots to target directory', null)
  .parse(process.argv);

let opts = 0;
if(typeof program.description === 'string')
  opts++;
if(typeof program.id === 'string')
  opts++;
if(typeof program.url === 'string')
  opts++;
if((opts !== 1) && (program.list !== true)) {
  console.log('Error: you need to specify exactly one descriptor for the log');
  program.help();
}

const webcrypto = new WebCrypto();
CTUtils.setWebCrypto(webcrypto);
CTUtils.setFetch(fetch);

const logHelper = new CTUtils.CTLogHelper();
let log, ctMonitor;

logHelper.fetch(CTUtils.CTLogHelper.lists.google).then(res => {
  return logHelper.generateIds();
}).then(res => {
  if(program.list === true) {
    logHelper.logs.forEach(log => {
      const idView = new Uint8Array(log.logId);
      let id = '';

      for(let i = 0; i < idView.length; i++) {
        if(i !== 0)
          id += ':';
        if(idView[i] < 0x10)
          id += ('0' + idView[i].toString(16));
        else
          id += idView[i].toString(16);
      }

      console.log(`- ${log.description}`);
      console.log(`  URL: ${log.url}`);
      console.log(`  ID: ${id}`);
      console.log(`  Operator: ${log.operators.join(', ')}`);
    });

    process.exit(0);
  }

  if(typeof program.description === 'string')
    log = logHelper.findByDescription(program.description);
  if(typeof program.id === 'string') {
    let id = program.id.replace(':', '');
    if(id.length !== 64) {
      console.log('Error: Invalid id');
      process.exit(1);
    }

    let idView = new Uint8Array(32);
    for(let i = 0; i < 32; i++) {
      idView[i] = parseInt(id.substr(0, 2), 16);
      id = id.substr(2);
    }

    log = logHelper.findById(idView.buffer);
  }
  if(typeof program.url === 'string')
    log = logHelper.findByUrl(program.url);

  if(log === null) {
    console.log('Error: Cannot find log.');
    process.exit(1);
  }

  console.log(`Using ${log.description}`);
  console.log(`URL: ${log.url}`);
  console.log(`ID: ${pvutils.bufferToHexCodes(log.logId)}`);
  console.log(`Operator: ${log.operators.join(', ')}`);

  return log.getRoots();
}).then(roots => {
  roots.forEach(root => {
    console.log(`- ${rdnToText(root.subject)}`);
  });

  if(program.output !== null) {
    let keyHashPromises = [];

    roots.forEach(root => {
      keyHashPromises.push(root.getKeyHash().then(hash => {
        return { hash, cert: root };
      }));
    });

    return Promise.all(keyHashPromises);
  } else {
    return null;
  }
}).then(keyHashes => {
  if(keyHashes !== null) {
    keyHashes.forEach(keyHash => {
      const dest = path.join(program.output,
        pvutils.bufferToHexCodes(keyHash.hash) + '.pem');
      fs.writeFileSync(dest, certToPEM(keyHash.cert));
    });
  }
});

