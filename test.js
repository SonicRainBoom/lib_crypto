'use strict';
var auth   = require('./lib/crypto');
var srbEvent = require('lib_srbevent');

setTimeout(
  () => {
    console.error('timeout after 30 sec.');
    process.exit(1);
  }, 30000
);

//TODO: Write tests

srbEvent.SRBEvent.info('no tests yet');

process.exit(0);
