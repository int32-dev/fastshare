import { Component, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { EncryptionService } from '../services/encryption.service';
import { SharecodeService } from '../sharecode.service';
import { WebsocketJsonMessage } from '../util/websocket/websocket-json-message';
import { ClientInfo } from '../util/websocket/websocket';

@Component({
  selector: 'app-send',
  standalone: true,
  imports: [FormsModule],
  templateUrl: './send.component.html',
  styleUrl: './send.component.css',
})
export class SendComponent {
  public data = signal('');
  public sharePairCode = signal('');

  public constructor(
    private encryptionService: EncryptionService,
    private sharecodeService: SharecodeService
  ) {}

  public async send() {
    const shareCode = this.sharecodeService.getShareCode();
    const keypair = await this.encryptionService.getKeyPair();
    const pubKeyBytes = await this.encryptionService.getPubKeyBytes(keypair);

    const params = new URLSearchParams();
    params.append('pubkey', this.encryptionService.toBase64(pubKeyBytes));

    const saltBytes = this.encryptionService.getRandomSalt();
    const salt = this.encryptionService.toBase64(saltBytes);
    params.append('salt', salt);

    const signature = await this.encryptionService.sign(
      shareCode,
      pubKeyBytes,
      saltBytes
    );
    params.append('hmac', this.encryptionService.toBase64(signature));

    console.log(params.toString());

    const uri = new URL(window.location.href);
    uri.protocol = window.location.protocol == 'https:' ? 'wss' : 'ws';
    uri.hostname = window.location.hostname;
    uri.port = '8080';
    uri.pathname = '/ws';
    uri.search = params.toString();

    let gotPairCode = false;
    let gotReceiverInfo = false;

    const ws = new WebSocket(uri.toString());

    ws.onmessage = async (event) => {
      if (!gotPairCode) {
        const message =
          WebsocketJsonMessage.fromWebsocketMessage<string>(event);
        if (message.route != 'pairCode') {
          ws.close(1002);
          throw new Error('Unexpected message');
        }

        gotPairCode = true;
        this.sharePairCode.set(shareCode + message.payload);
        return;
      }

      if (!gotReceiverInfo) {
        const message =
          WebsocketJsonMessage.fromWebsocketMessage<ClientInfo>(event);
        if (message.route != 'receiverInfo') {
          ws.close(1002);
          throw new Error('Unexpected message');
        }

        gotReceiverInfo = true;

        const rPubBytes = this.encryptionService.fromBase64(message.payload.PubKey);
        const rpubKey = await this.encryptionService.importPubKey(rPubBytes);

        const rSalt = this.encryptionService.fromBase64(message.payload.Salt);
        const rHmac = this.encryptionService.fromBase64(message.payload.Hmac);

        const valid = await this.encryptionService.verify(shareCode, rPubBytes, rHmac, rSalt);
        if (!valid) {
          ws.close(1002);
          throw new Error('Invalid signature');
        }

        const rawData = new TextEncoder().encode(this.data());

        ws.send(
          'size\n' +
          rawData.byteLength
        );

        const aesKey = await this.encryptionService.getAesKey(shareCode, keypair, rpubKey);

        const nonce = new Uint8Array(12);

        let offset = 0;
        const chunk_size = 20;
        while (offset < rawData.byteLength) {
          const chunk = rawData.slice(offset, Math.min(offset + chunk_size, rawData.byteLength));
          const encrypted = await window.crypto.subtle.encrypt(
            {
              name: 'AES-GCM',
              iv: nonce,
              additionalData: new TextEncoder().encode(shareCode),
            },
            aesKey,
            chunk
          );

          ws.send(encrypted);
          offset += chunk.byteLength;
          this.encryptionService.incrementNonce(nonce);
        }

        setTimeout(() => {
          ws.close(1000);
          console.log('done');
        }, 1000)
      }
    };
  }
}
