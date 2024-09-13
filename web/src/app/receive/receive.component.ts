import { Component, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { EncryptionService } from '../services/encryption.service';
import { WebsocketJsonMessage } from '../util/websocket/websocket-json-message';
import { ClientInfo } from '../util/websocket/websocket';
import { RouterLink } from '@angular/router';
import { UrlHelper } from '../util/url-helper';

const PAIR_CODE_LENGTH = 4;

@Component({
  selector: 'app-receive',
  standalone: true,
  imports: [FormsModule, RouterLink],
  templateUrl: './receive.component.html',
  styleUrl: './receive.component.css',
})
export class ReceiveComponent {
  public shareCode = signal('');
  public receivedData = signal('');

  public constructor(private encryptionService: EncryptionService) {}

  public async receive() {
    const sharePairCode = this.shareCode();
    if (sharePairCode.length <= PAIR_CODE_LENGTH) {
      throw new Error('Invalid pair code');
    }

    const pairCode = sharePairCode.substring(
      sharePairCode.length - PAIR_CODE_LENGTH
    );
    const shareCode = sharePairCode.substring(
      0,
      sharePairCode.length - PAIR_CODE_LENGTH
    );

    console.log('Receiving data...');


    const encryptionInfo = await this.encryptionService.getInfo();
    const params = await this.encryptionService.getQueryParams(shareCode);

    params.append('paircode', pairCode);

    console.log(params.toString());

    const uri = UrlHelper.buildUrl(params);

    let gotSenderInfo = false;
    let gotSize = false;

    const ws = new WebSocket(uri.toString());

    let sPubBytes: ArrayBuffer;
    let spubKey: CryptoKey;
    let sSalt: ArrayBuffer;
    let sHmac: ArrayBuffer;
    let aesKey: CryptoKey;
    let size: number;
    const nonce = new Uint8Array(12);
    let offset = 0;
    const chunk_size = 8192*2;
    const aead_overhead = 16;
    const enc_chunk_size = chunk_size + aead_overhead;

    let encryptedData: Uint8Array;

    ws.onclose = async (event: CloseEvent) => {
      if (event.code != 1000) {
        throw new Error('Connection closed unexpectedly');
      }

      let readOffset = 0;
      let decryptedOffset = 0;

      console.log('Decrypting data');

      while (readOffset < offset) {
        const chunk = encryptedData.slice(
          readOffset,
          Math.min(readOffset + enc_chunk_size, encryptedData.byteLength)
        );

        console.log('sliced chunk', readOffset);

        const decrypted = await window.crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: new TextEncoder().encode(shareCode),
          },
          aesKey,
          chunk
        );
        
        console.log('Decrypted chunk', decryptedOffset);
        console.log(decrypted);
        
        encryptedData.set(new Uint8Array(decrypted), decryptedOffset);
        decryptedOffset += decrypted.byteLength;
        readOffset += enc_chunk_size;
        this.encryptionService.incrementNonce(nonce);
        console.log('Incremented nonce');
      }

      console.log('Received data');
      const plainText = new TextDecoder().decode(encryptedData.slice(0, size));
      console.log(plainText);
      this.receivedData.set(plainText);
    };

    ws.onmessage = async (event: MessageEvent) => {
      if (!gotSenderInfo) {
        const message =
          WebsocketJsonMessage.fromWebsocketMessage<ClientInfo>(event);
        if (message.route != 'senderInfo') {
          ws.close(1002);
          throw new Error('Unexpected message');
        }

        gotSenderInfo = true;

        sPubBytes = this.encryptionService.fromBase64(message.payload.PubKey);
        spubKey = await this.encryptionService.importPubKey(sPubBytes);

        sSalt = this.encryptionService.fromBase64(message.payload.Salt);
        sHmac = this.encryptionService.fromBase64(message.payload.Hmac);

        const valid = await this.encryptionService.verify(
          shareCode,
          sPubBytes,
          sHmac,
          sSalt
        );

        if (!valid) {
          ws.close(1002);
          throw new Error('Invalid signature');
        }

        ws.send(
          'receiverInfo\n' +
            JSON.stringify(<ClientInfo>{
              PubKey: params.get('pubkey'),
              Salt: params.get('salt'),
              Hmac: params.get('hmac'),
            })
        );

        aesKey = await this.encryptionService.getAesKey(
          shareCode,
          encryptionInfo.keyPair,
          spubKey
        );

        return;
      }

      if (!gotSize) {
        const message =
          WebsocketJsonMessage.fromWebsocketMessage<number>(event);

        if (message.route != 'size') {
          ws.close(1002);
          throw new Error('Unexpected message');
        }

        size = message.payload;
        console.log('Size: ' + size);
        encryptedData = new Uint8Array(
          size + Math.ceil(size / chunk_size) * aead_overhead
        );

        gotSize = true;
        return;
      }

      try {
        const arrData = await event.data.arrayBuffer();
        const data = new Uint8Array(arrData);

        encryptedData.set(new Uint8Array(data), offset);

        offset += data.byteLength;
      } catch (e) {
        console.error(e);
        ws.close(1002);
      }
    };
  }
}
