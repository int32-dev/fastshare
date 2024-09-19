import { Component, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CHUNK_SIZE, EncryptionService } from '../services/encryption.service';
import { SharecodeService } from '../sharecode.service';
import { WebsocketJsonMessage } from '../util/websocket/websocket-json-message';
import { ClientInfo } from '../util/websocket/websocket';
import { UrlHelper } from '../util/url-helper';

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
  public files: File[] = [];

  public constructor(
    private encryptionService: EncryptionService,
    private sharecodeService: SharecodeService
  ) {}

  public fileChange(event: any) {
    this.files = event?.target?.files || [];
  }

  public async sendFile() {
    if (!this.files) {
      return;
    }

    if (this.files.length > 1) {
      alert("Can only send one file.");
      return ;
    }

    const size = this.files[0].size;

    const reg = await navigator.serviceWorker.ready;

    const formaData = new FormData();
    formaData.append('file', this.files[0]);

    fetch('/sendFile', {
      method: 'POST',
      body: formaData
    });

    console.log('sent?');

    // await this.sendData(this.files[0].stream(), size);
  }

  public async send() {
    const rawData = new TextEncoder().encode(this.data());

    let offset = 0;

    const stream = new ReadableStream({
      type: 'bytes',
      pull(controller) {
        if (controller.byobRequest?.view) {
          const view: ArrayBufferView = controller.byobRequest.view;
          const arr = new Uint8Array(view.buffer);

          const remaining = rawData.length - offset;
          const toWrite = Math.min(view.byteLength, remaining);

          arr.set(rawData.slice(offset, offset + toWrite), 0);
          controller.byobRequest.respond(toWrite);
        }
      }
    });

    await this.sendData(stream, rawData.byteLength);
  }

  private async sendData(data: ReadableStream, size: number) {
    const shareCode = this.sharecodeService.getShareCode();
    const encryptionInfo = await this.encryptionService.getInfo();
    const params = await this.encryptionService.getQueryParams(shareCode);

    console.log(params.toString());

    const uri = UrlHelper.buildUrl(params);

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

        const rPubBytes = this.encryptionService.fromBase64(
          message.payload.PubKey
        );
        const rpubKey = await this.encryptionService.importPubKey(rPubBytes);

        const rSalt = this.encryptionService.fromBase64(message.payload.Salt);
        const rHmac = this.encryptionService.fromBase64(message.payload.Hmac);

        const valid = await this.encryptionService.verify(
          shareCode,
          rPubBytes,
          rHmac,
          rSalt
        );
        if (!valid) {
          ws.close(1002);
          throw new Error('Invalid signature');
        }

        ws.send('size\n' + size);

        const aesKey = await this.encryptionService.getAesKey(
          shareCode,
          encryptionInfo.keyPair,
          rpubKey
        );

        const nonce = new Uint8Array(12);

        let chunkBuf = new ArrayBuffer(CHUNK_SIZE);

        try {
          const r = data.getReader({ mode: 'byob' });

          let offset = 0;
          while (offset < size) {
            const d = await r.read(new Uint8Array(chunkBuf, 0, CHUNK_SIZE));
  
            if (d.value) {
              chunkBuf = d.value.buffer;
  
              const encrypted = await window.crypto.subtle.encrypt(
                {
                  name: 'AES-GCM',
                  iv: nonce,
                  additionalData: new TextEncoder().encode(shareCode),
                },
                aesKey,
                d.value,
              );
  
              ws.send(encrypted);
              offset += d.value.byteLength;
              this.encryptionService.incrementNonce(nonce);
            }
  
            if (d.done) {
              break;
            }
          }
        }
        catch (e) {
          console.error(e);
        }

        setTimeout(() => {
          ws.close(1000);
          console.log('done');
        }, 1000);
      }
    };
  }
}
