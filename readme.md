# Fastshare

Fastshare is a simple and secure application for securely sharing files between devices without the need for an account. The sender and client find eachother automatically using the share code, so there's no need to enter or find ip addresses. All messages are end to end encrypted so nobody can steal your data.

Currently, the only supported sharing method is cli -> cli on a local network. Clients will use UDP Broadcast messages to discover each other automatically, and then initiate the transfer.

### CLI Usage:
```bash
fastshare <command> <options>

Commands:
send OR s:
  options:
  -f <filename>: file to send
  -m <message>: message to send
  -c: lets you enter your own "share code" (will be prompted to enter after hitting enter)
  



receive OR r: receive a file
  options:
  -f <filename>: write output to a file instead of printing to stdout
  -c <share code>: specify share code in args instead of being prompted for the share code.

Generic Options:
-p, --port: port to listen on for sharing (defaults to 65432)
```

## Current Planned Features:
Web UI: plan is to create a separate fastshare-server command that you can run to host a simple webserver with a web ui that you can send files / messages on. This will expand the supported devices to pretty much anything that has a modern web browser.
Online Mode: Add the option to share through a web relay, so you can share with devices outside your local network, and so you can share from web ui -> terminal and terminal -> web ui.

## Building
Make sure you have `make` and `go` installed, then run `make build-<platform>` (look in the make file for targets...) or run `make all` and run the appropriate file...

## Inner Workings
Local Sharing:
A sender and client discover eachother on the local network by using UDP Broadcast messages.

The message contents are actually a simple ECDH handshake, with a signature using the share code.
First the sender and receiver will generate a new X25519 keypair for ecdh. 

Sender message: ecdh public key bytes + hmac(ecdh public key, share code)
Receiver message: ecdh public key bytes + hmac(ecdh public key, share code)

Each endpoint will verify the public key they receive by generating their own hmac with the share code, so they know that the device sending the message knows the share code.

Each endpoint calculates a shared aes key using the ecdh key exchange.

After this, the sender will switch to listening on the same port using TCP instead of UDP.
The receiver will connect to the sender through TCP.
The sender then sends the size of the plaintext to the receiver. (UNENCRYPTED) (doesn't matter, they can get the size by calculating the aead overhead and ciphertext size anyways.)

All following messages are encrypted using AES GCM, and an incremented nonce.

Messages are split into chunks of 16kb currently. Not using streams because go doesn't implement streaming ciphers in the std lib, and then you can verify that nobody is messing with the ciphertext before receiving the whole file. Also, when the web method is added, there's no streaming cipher support for web browsers / js so I'd have to change it anyways.

Also, splitting into chunks so you don't have to hold the entire file in ram.

Currently there's a limit of 64GB that can be safely sent using this method, at some point I might update the nonce incrementer to detect when it's full and rotate the key somehow. But 64GB is pretty big and I'm not using it for files that large.
