'use strict';
/**
 * Copyright 2016 Hendrik 'T4cC0re' Meyer & SonicRainBoom Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {SRBEvent} from 'lib_srbevent';
let forge          = require('node-forge');
var pki            = forge.pki;
var ssh            = forge.ssh;
var hash           = forge.sha512.create();
// var defaultKeySize = 512;
var defaultKeySize = 4096;

export interface BigInteger {
  s: number
  t: number
  data: Array<number>
}

export interface Key {
  e: BigInteger
  n: BigInteger
}

export interface PublicKey extends Key {
  encrypt(): any
  verify(): any
}

export interface PrivateKey extends Key {
  d: BigInteger
  dP: BigInteger
  dQ: BigInteger
  p: BigInteger
  q: BigInteger
  qInv: BigInteger
  sign(): any
  decrypt(): any
}

export class KeyStore {
  static generate(bits?: number): KeyStore {
    bits = bits || defaultKeySize;
    if (bits < defaultKeySize) {
      SRBEvent.warn(`The selected key-size of ${bits} is discouraged and below the recommendation of ${defaultKeySize}. It might be possible for an attacker to impersonate!`);
    }
    let keypair             = pki.rsa.generateKeyPair(
      {
        bits: bits || defaultKeySize,
        e   : 0x10001
      }
    );
    let store               = new KeyStore();
    store.privateKey        = keypair.privateKey;
    store.publicKey         = keypair.publicKey;
    store.publicFingerprint = ssh.getPublicKeyFingerprint(
      store.publicKey,
      {
        encoding: 'hex',
        md      : hash
      }
    );
    return store;
  }

  static fromPrivateKey(privateKey: PrivateKey): KeyStore {
    let store               = new KeyStore();
    store.publicKey         = {
      e      : privateKey.e,
      n      : privateKey.n,
      encrypt: ()=> {
      },
      verify : ()=> {
      },
    };
    store.privateKey        = privateKey;
    store.publicFingerprint = ssh.getPublicKeyFingerprint(
      store.publicKey,
      {
        encoding: 'hex',
        md      : hash
      }
    );
    return store;
  }

  static fromPrivateKeyPem(privateKey: string): KeyStore {
    let store               = new KeyStore();
    store.privateKey        = <PrivateKey> pki.privateKeyFromPem(privateKey);
    store.publicKey         = {
      e      : store.privateKey.e,
      n      : store.privateKey.n,
      //TODO: Fix this to use the actual prototype function of node-forge's implementation.
      encrypt: ()=> {
      },
      verify : ()=> {
      },
    };
    store.publicFingerprint = ssh.getPublicKeyFingerprint(
      store.publicKey,
      {
        encoding: 'hex',
        md      : hash
      }
    );
    return store;
  }

  public publicKey: PublicKey;
  public publicFingerprint: string;
  public privateKey: PrivateKey;

  static fromPemKeyPair(publicKey?: string, privateKey?: string): KeyStore {
    let store = new KeyStore();
    if (publicKey) {
      if (publicKey.indexOf('-----BEGIN PUBLIC KEY-----') === 0) {
        store.publicKey = <PublicKey>pki.publicKeyFromPem(publicKey);
      }
    }
    if (privateKey) {
      if (privateKey.indexOf('------BEGIN RSA PRIVATE KEY-----') === 0) {
        store.privateKey = <PrivateKey>pki.privateKeyFromPem(privateKey);
      }
    }
    if (!store.publicKey) {
      throw new Error('Could not extract public key');
    }
    if (!store.privateKey && privateKey) {
      throw new Error('Could not extract private key');
    }
    if ((store.publicKey.e !== store.privateKey.e)
        || (store.publicKey.n !== store.privateKey.n)
    ) {
      store.publicFingerprint = <string> ssh.getPublicKeyFingerprint(
        store.publicKey,
        {
          encoding: 'hex',
          md      : hash
        }
      );
    }
    return store;
  }

  exportPublicKey(): string {
    return pki.publicKeyToPem(this.publicKey);
  }

  exportPrivateKey(): string {
    return pki.privateKeyToPem(this.privateKey);
  }
}
