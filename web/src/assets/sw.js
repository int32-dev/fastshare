/**
 * @type {ServiceWorkerGlobalScope}
 */
const sw = self;

sw.addEventListener("install", (event) => {
  console.log("Service worker installed");
  sw.skipWaiting();
});

sw.addEventListener("activate", (event) => {
  console.log("Service worker activated");
  event.waitUntil(sw.clients.claim());
});

sw.addEventListener("message", (event) => {
  console.log("Received message", event.data);
  if (event.data.size > 0) {
    sendData(event.data.file, event.data.size);
  }
});

sw.addEventListener("fetch", async (event) => {
  console.log("Fetch event", event.request.url);

  if (event.request.url.includes("/sendFile")) {
    const data = await event.request.formData();
    /**
     * @type {File}
     */
    const file = data.get("file");
    console.log("file:", file);
    try {
      await sendData(file.stream(), file.size);
    } catch (e) {
      console.error(e);
      const response = new Response("Error", {
        status: 500,
        statusText: "Internal Server Error",
        headers: {
          "Content-Type": "text/plain",
        },
      });

      event.respondWith(response);
    }

    const response = new Response("OK", {
      status: 200,
      statusText: "OK",
      headers: {
        "Content-Type": "text/plain",
      },
    });

    event.respondWith(response);
  } else if (event.request.url.includes("/receiveFile")) {
    const url = new URL(event.request.url);
    const sharePairCode = url.searchParams.get("paircode");
    console.log("share pair code: ", sharePairCode);

    const stream = new ReadableStream({
      start(controller) {
        console.log("created controller...");
        receiveData(sharePairCode, controller);
      },
    });

    const response = new Response(stream, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": "attachment; filename=received.bin",
      },
    });

    event.respondWith(response);
  }
});

/**
 *
 * @returns {string}
 */
function getShareCode() {
  return "BluePenguinBouncer";
}

/**
 * type ClientInfo = {
 *    PubKey: string;
 *    Salt: string;
 *    Hmac: string;
 * }
 */

class WebsocketJsonMessage {
  /**
   *
   * @param {string} route
   * @param {any} payload
   */
  constructor(route, payload) {
    this.route = route;
    this.payload = payload;
  }
}

/**
 *
 * @param {MessageEvent} event
 * @returns
 */
function parseWsTextMessage(event) {
  if (typeof event.data !== "string") {
    throw new Error("Expected string message");
  }

  const parts = event.data.split("\n", 2);
  if (parts.length != 2) {
    throw new Error("Invalid message format");
  }

  const data = JSON.parse(parts[1]);

  return new WebsocketJsonMessage(parts[0], data);
}

/**
 *
 * @param {URLSearchParams} params
 * @returns {string}
 */
function buildUrl(params) {
  const uri = new URL(sw.location.href);
  uri.protocol = sw.location.protocol == "https:" ? "wss" : "ws";
  uri.hostname = sw.location.hostname;
  uri.port = sw.location.port == "4200" ? "8080" : sw.location.port;
  uri.pathname = "/ws";
  uri.search = params.toString();

  return uri.toString();
}

/**
 *
 * @param {ReadableStream} data
 * @param {number} size
 */
async function sendData(data, size) {
  const shareCode = getShareCode();
  const encryptionInfo = await getInfo();
  const params = await getQueryParams(shareCode);

  console.log(params.toString());

  const uri = buildUrl(params);
  console.log(uri.toString());

  let gotPairCode = false;
  let gotReceiverInfo = false;

  const ws = new WebSocket(uri.toString());

  ws.onmessage = async (event) => {
    if (!gotPairCode) {
      const message = parseWsTextMessage(event);
      if (message.route != "pairCode") {
        ws.close(1002);
        throw new Error("Unexpected message");
      }

      gotPairCode = true;
      console.log("Pair code", shareCode + message.payload);
      return;
    }

    if (!gotReceiverInfo) {
      const message = parseWsTextMessage(event);
      if (message.route != "receiverInfo") {
        ws.close(1002);
        throw new Error("Unexpected message");
      }

      gotReceiverInfo = true;

      const rPubBytes = fromBase64(message.payload.PubKey);
      const rpubKey = await importPubKey(rPubBytes);

      const rSalt = fromBase64(message.payload.Salt);
      const rHmac = fromBase64(message.payload.Hmac);

      const valid = await verify(shareCode, rPubBytes, rHmac, rSalt);
      if (!valid) {
        ws.close(1002);
        throw new Error("Invalid signature");
      }

      ws.send("size\n" + size);

      const aesKey = await getAesKey(
        shareCode,
        encryptionInfo.keyPair,
        rpubKey
      );

      const nonce = new Uint8Array(12);

      let chunkBuf = new ArrayBuffer(CHUNK_SIZE);

      try {
        const r = data.getReader({ mode: "byob" });

        let offset = 0;
        while (offset < size) {
          const d = await r.read(new Uint8Array(chunkBuf, 0, CHUNK_SIZE));

          if (d.value) {
            chunkBuf = d.value.buffer;

            const encrypted = await self.crypto.subtle.encrypt(
              {
                name: "AES-GCM",
                iv: nonce,
                additionalData: new TextEncoder().encode(shareCode),
              },
              aesKey,
              d.value
            );

            ws.send(encrypted);
            offset += d.value.byteLength;
            incrementNonce(nonce);
          }

          if (d.done) {
            break;
          }
        }
      } catch (e) {
        console.error(e);
      }

      setTimeout(() => {
        ws.close(1000);
        console.log("done");
      }, 1000);
    }
  };
}

class EncryptionInfo {
  /**
   *
   * @param {CryptoKeyPair} keyPair
   * @param {ArrayBuffer} pubKeyBytes
   * @param {Uint8Array} salt
   */
  constructor(keyPair, pubKeyBytes, salt) {
    this.keyPair = keyPair;
    this.pubKeyBytes = pubKeyBytes;
    this.salt = salt;
  }

  /**
   *
   * @returns {Promise<EncryptionInfo>}
   */
  static async create() {
    const keyPair = await getKeyPair();
    const pubKeyBytes = await getPubKeyBytes(keyPair);
    const salt = getRandomSalt();

    return new EncryptionInfo(keyPair, pubKeyBytes, salt);
  }
}

const CHUNK_SIZE = 8192 * 2;
const AEAD_OVERHEAD = 16;
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + AEAD_OVERHEAD;

/**
 * @type {EncryptionInfo}
 */
let encryptionInfo = null;

/**
 *
 * @param {string} shareCode
 * @returns {Promise<URLSearchParams>}
 */
async function getQueryParams(shareCode) {
  const encryptionInfo = await getInfo();
  const params = new URLSearchParams();
  params.append("pubkey", toBase64(encryptionInfo.pubKeyBytes));
  params.append("salt", toBase64(encryptionInfo.salt));

  const signature = await sign(
    shareCode,
    encryptionInfo.pubKeyBytes,
    encryptionInfo.salt
  );

  params.append("hmac", toBase64(signature));

  return params;
}

/**
 *
 * @returns {Promise<EncryptionInfo>}
 */
async function getInfo() {
  if (encryptionInfo == null) {
    encryptionInfo = await EncryptionInfo.create();
  }

  return encryptionInfo;
}

/**
 *
 * @returns {Promise<CryptoKeyPair>}
 */
async function getKeyPair() {
  const key = await self.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    false,
    ["deriveKey", "deriveBits"]
  );
  return key;
}

/**
 *
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function toBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

/**
 *
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
function fromBase64(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
}

/**
 *
 * @param {CryptoKeyPair} keypair
 * @returns {Promise<ArrayBuffer>}
 */
async function getPubKeyBytes(keypair) {
  return await self.crypto.subtle.exportKey("raw", keypair.publicKey);
}

/**
 * @param {CryptoKeyPair} keypair
 * @returns {Promise<string>}
 */
async function getPubKeyBase64(keypair) {
  const pubkeyBytes = await getPubKeyBytes(keypair);
  return toBase64(pubkeyBytes);
}

/**
 *
 * @returns {Uint8Array}
 */
function getRandomSalt() {
  return self.crypto.getRandomValues(new Uint8Array(16));
}

/**
 *
 * @param {ArrayBuffer} pubKeyBytes
 * @returns {Promise<CryptoKey>}
 */
async function importPubKey(pubKeyBytes) {
  console.log(pubKeyBytes);
  return await self.crypto.subtle.importKey(
    "raw",
    pubKeyBytes,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

/**
 *
 * @param {string} shareCode
 * @param {ArrayBuffer} salt
 * @returns {Promise<CryptoKey>}
 */
async function getHmacKey(shareCode, salt) {
  const shareCodeBytes = new TextEncoder().encode(shareCode);
  const pbkey = await self.crypto.subtle.importKey(
    "raw",
    shareCodeBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const hmacKey = await self.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-512",
    },
    pbkey,
    {
      name: "HMAC",
      hash: "SHA-512",
    },
    false,
    ["sign", "verify"]
  );

  return hmacKey;
}

/**
 *
 * @param {string} shareCode
 * @param {ArrayBuffer} pubKeyBytes
 * @param {ArrayBuffer} expectedSignature
 * @param {ArrayBuffer} salt
 * @returns {Promise<boolean>}
 */
async function verify(shareCode, pubKeyBytes, expectedSignature, salt) {
  const hmacKey = await getHmacKey(shareCode, salt);
  const valid = await self.crypto.subtle.verify(
    "HMAC",
    hmacKey,
    expectedSignature,
    pubKeyBytes
  );

  return valid;
}

/**
 *
 * @param {string} shareCode
 * @param {ArrayBuffer} pubKeyBytes
 * @param {Uint8Array} salt
 * @returns {Promise<ArrayBuffer>}
 */
async function sign(shareCode, pubKeyBytes, salt) {
  const hmacKey = await getHmacKey(shareCode, salt);

  const signature = await self.crypto.subtle.sign("HMAC", hmacKey, pubKeyBytes);

  return signature;
}

/**
 *
 * @param {string} shareCode
 * @param {CryptoKeyPair} keyPair
 * @param {CryptoKey} pubKey
 */
async function getAesKey(shareCode, keyPair, pubKey) {
  const hkdfKey = await self.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: pubKey,
    },
    keyPair.privateKey,
    {
      name: "HKDF",
      hash: "SHA-512",
      salt: new ArrayBuffer(0),
      info: new TextEncoder().encode(shareCode),
    },
    false,
    ["deriveKey"]
  );

  const aesKey = await self.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-512",
      salt: new ArrayBuffer(0),
      info: new TextEncoder().encode(shareCode),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return aesKey;
}

/**
 *
 * @param {Uint8Array} nonce
 */
function incrementNonce(nonce) {
  for (let i = 0; i < nonce.length; i++) {
    if (nonce[i] === 255) {
      nonce[i] = 0;
    } else {
      nonce[i]++;
      break;
    }
  }
}

const PAIR_CODE_LENGTH = 4;

class Queue {
  constructor() {
    this._queue = [];
    this._closed = false;
  }

  enqueue(item) {
    if (this._closed) {
      throw new Error("Queue is closed");
    }

    this._queue.push(item);
  }

  dequeue() {
    if (this._queue.length == 0) {
      return null;
    }

    return this._queue.shift();
  }

  close() {
    this._closed = true;
  }

  get closed() {
    return this._closed;
  }
}

/**
 *
 * @param {string} sharePairCode
 * @param {ReadableStreamController} responseStream
 */
async function receiveData(sharePairCode, responseStream) {
  //   try {
  if (sharePairCode.length <= PAIR_CODE_LENGTH) {
    throw new Error("Invalid pair code");
  }

  console.log("Pair code: " + sharePairCode);

  const pairCode = sharePairCode.substring(
    sharePairCode.length - PAIR_CODE_LENGTH
  );

  const shareCode = sharePairCode.substring(
    0,
    sharePairCode.length - PAIR_CODE_LENGTH
  );

  console.log("Receiving data...");

  const encryptionInfo = await getInfo();
  const params = await getQueryParams(sharePairCode);

  params.append("paircode", pairCode);

  console.log(params.toString());

  const uri = buildUrl(params);

  let gotSenderInfo = false;
  let gotSize = false;

  console.log(uri);

  const ws = new WebSocket(uri.toString());

  let sPubBytes;
  let spubKey;
  let sSalt;
  let sHmac;
  let aesKey;
  let size;
  const nonce = new Uint8Array(12);
  let offset = 0;
  let queue = new Queue();
  let startedProcessing = false;

  ws.onclose = async (event) => {
    console.log("Connection closed", event);
    if (event.code != 1000) {
      console.log("error");
      responseStream.error(new Error("Connection closed unexpectedly"));
      throw new Error("Connection closed unexpectedly");
    }

    //   responseStream.close();
  };

  ws.onmessage = async (event) => {
    if (!gotSenderInfo) {
      const message = parseWsTextMessage(event);
      if (message.route != "senderInfo") {
        ws.close(1002);
        throw new Error("Unexpected message");
      }

      gotSenderInfo = true;

      console.log(message);

      sPubBytes = fromBase64(message.payload.PubKey);
      console.log("import pubkey");
      spubKey = await importPubKey(sPubBytes);
      console.log("done import");

      sSalt = fromBase64(message.payload.Salt);
      sHmac = fromBase64(message.payload.Hmac);

      const valid = await verify(shareCode, sPubBytes, sHmac, sSalt);

      if (!valid) {
        ws.close(1002);
        console.log("invalid signature");
        throw new Error("Invalid signature");
      }

      console.log("valid signature");

      const signature = await sign(
        shareCode,
        encryptionInfo.pubKeyBytes,
        encryptionInfo.salt
      );

      ws.send(
        "receiverInfo\n" +
          JSON.stringify({
            PubKey: toBase64(encryptionInfo.pubKeyBytes),
            Salt: toBase64(encryptionInfo.salt),
            Hmac: toBase64(signature),
          })
      );

      console.log("sent receiver info");

      aesKey = await getAesKey(shareCode, encryptionInfo.keyPair, spubKey);

      return;
    }

    if (!gotSize) {
      const message = parseWsTextMessage(event);

      if (message.route != "size") {
        ws.close(1002);
        throw new Error("Unexpected message");
      }

      size = parseInt(message.payload);
      console.log("Size: " + size);

      gotSize = true;
      return;
    }

    queue.enqueue(event.data);

    if (!startedProcessing) {
      startedProcessing = true;
      async function process() {
        if (queue.closed) {
          return;
        }

        const msg = queue.dequeue();
        if (msg == null) {
          setTimeout(process, 0);
        }

        const arrData = await msg.arrayBuffer();
        const data = new Uint8Array(arrData);

        console.log("decrypt...", nonce);
        const decrypted = await self.crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: nonce,
            additionalData: new TextEncoder().encode(shareCode),
          },
          aesKey,
          data
        );

        console.log("decrypted:");

        responseStream.enqueue(new Uint8Array(decrypted));

        incrementNonce(nonce);
        offset += data.byteLength;

        if (offset >= size) {
          queue.close();
          responseStream.close();
          // ws.close(1000);
          return;
        }

        setTimeout(process, 0);
      }

      process();
    }
  };
  //   } catch (e) {
  //     responseStream.error(e);
  //     throw e;
  //   }
}
