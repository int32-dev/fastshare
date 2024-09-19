import { Component, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AEAD_OVERHEAD, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, EncryptionService } from '../services/encryption.service';
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
    const reg = await navigator.serviceWorker.ready;

    const sharePairCode = this.shareCode();
    console.log('Receiving data...');

    const link = document.createElement('a');
    const params = new URLSearchParams();
    params.append('paircode', sharePairCode);
    link.href = "/receiveFile?" + params.toString();

    document.querySelector('body')?.appendChild(link);

    link.click();
  }
}
