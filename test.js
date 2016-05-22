'use strict';
var crypto   = require('./lib/crypto');
var srbEvent = require('lib_srbevent');

setTimeout(
  () => {
    console.error('timeout after 30 sec.');
    process.exit(1);
  }, 30000
);

try {
  var ks1  = crypto.KeyStore.generate(512);
  var pem1 = ks1.exportPublicKey();
  var pem2 = ks1.exportPrivateKey();

  var ks2  = crypto.KeyStore.fromPemKeyPair(pem1, pem2);
  console.log(ks1.privateKey.d.equals(ks2.privateKey.d));
  console.log(ks1.publicKey.e.equals(ks2.publicKey.e));

  var ks3 = crypto.KeyStore.fromPrivateKeyPem(pem2);
  console.log(ks1.privateKey.d.equals(ks3.privateKey.d));
  console.log(ks1.publicKey.e.equals(ks3.publicKey.e));

  var ks4 = crypto.KeyStore.fromPrivateKey(ks1.privateKey);
  console.log(ks1.privateKey.d.equals(ks4.privateKey.d));
  console.log(ks1.publicKey.e.equals(ks4.publicKey.e));

  var ks5 = crypto.KeyStore.fromPemKeyPair(pem1);
  console.log(ks1.publicKey.e.equals(ks5.publicKey.e));
}catch (e){
  SRBEvent.fatal(e);
}

process.exit(0);
