import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root',
})
export class EncryptionService {
  constructor() {}

  public async getKeyPair(): Promise<CryptoKeyPair> {
    const key = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      ['deriveKey', 'deriveBits']
    );
    return key;
  }

  public toBase64(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  public fromBase64(base64: string): ArrayBuffer {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
  }

  public async getPubKeyBytes(keypair: CryptoKeyPair): Promise<ArrayBuffer> {
    return await window.crypto.subtle.exportKey('raw', keypair.publicKey);
  }

  public async getPubKeyBase64(keypair: CryptoKeyPair): Promise<string> {
    const pubkeyBytes = await this.getPubKeyBytes(keypair);
    return this.toBase64(pubkeyBytes);
  }

  public getRandomSalt(): Uint8Array {
    return window.crypto.getRandomValues(new Uint8Array(16));
  }

  public async importPubKey(pubKeyBytes: ArrayBuffer): Promise<CryptoKey> {
    return await window.crypto.subtle.importKey(
      'raw',
      pubKeyBytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    );
  }

  private async getHmacKey(
    shareCode: string,
    salt: ArrayBuffer
  ): Promise<CryptoKey> {
    const shareCodeBytes = new TextEncoder().encode(shareCode);
    const pbkey = await window.crypto.subtle.importKey(
      'raw',
      shareCodeBytes,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const hmacKey = await window.crypto.subtle.deriveKey(
      <Pbkdf2Params>{
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-512',
      },
      pbkey,
      <HmacKeyGenParams>{
        name: 'HMAC',
        hash: 'SHA-512',
      },
      false,
      ['sign', 'verify']
    );

    return hmacKey;
  }

  public async verify(
    shareCode: string,
    pubKeyBytes: ArrayBuffer,
    expectedSignature: ArrayBuffer,
    salt: ArrayBuffer
  ): Promise<boolean> {
    const hmacKey = await this.getHmacKey(shareCode, salt);
    const valid = await window.crypto.subtle.verify(
      'HMAC',
      hmacKey,
      expectedSignature,
      pubKeyBytes
    );

    return valid;
  }

  public async sign(
    shareCode: string,
    pubKeyBytes: ArrayBuffer,
    salt: Uint8Array
  ): Promise<ArrayBuffer> {
    const hmacKey = await this.getHmacKey(shareCode, salt);

    const signature = await window.crypto.subtle.sign(
      'HMAC',
      hmacKey,
      pubKeyBytes
    );

    return signature;
  }

  public async getAesKey(
    shareCode: string,
    keyPair: CryptoKeyPair,
    pubKey: CryptoKey
  ) {
    const hkdfKey = await window.crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: pubKey,
      },
      keyPair.privateKey,
      <HkdfParams>{
        name: 'HKDF',
        hash: 'SHA-512',
        salt: new ArrayBuffer(0),
        info: new TextEncoder().encode(shareCode),
      },
      true,
      ['deriveKey']
    );

    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-512',
        salt: new ArrayBuffer(0),
        info: new TextEncoder().encode(shareCode),
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    return aesKey;
  }

  public incrementNonce(nonce: Uint8Array) {
    for (let i = 0; i < nonce.length; i++) {
      if (nonce[i] === 255) {
        nonce[i] = 0;
      } else {
        nonce[i]++;
        break;
      }
    }
  }
}
