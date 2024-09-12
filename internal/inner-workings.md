# Inner Workings

## Defenitions:
- hmacsha512(messageToSign, salt, key)
- verifyMessage:
    > message is `ecdh pub key + salt + hmac`
    >
    > generate `hmacsha512(received ecdh pub key, salt, key)`
    >
    > verify that it matches received hmac

## Local Sharing:
### Sender:
- Generate share phrase, or use provided share phrase. Display to user.
- Generate a random salt
- Generate X25519 keypair
- Generate `hmacsha512(x25519 pub key, salt, share code)`
- store `message = x25519 pub key + salt + hmac` for later use
- Listen on udp port 65432 for broadcasts from receiver
- When a message is recieved, `verifyMessage`, respond with `message`
- if receiver message is invalid, ignore it
- if receiver message is valid, do hkdf(ecdh(private key, recv pub key), share code)
- use result for aes-gcm key
- send reciever `message` until they connect to tcp:65432
- when they connect to tcp:65432, send length of plaintext, and send encrypted data stream

### Receiver
- get shrae phrase from user
- generate random salt
- generate x25519 keypair
- generate `hmacsha512(x25519 pub key, salt, share code)`
- save `message = x25519 pub key + salt + hmac`
- broadcast message to all available subnets on port 65432
- listen for sender messages on 65432
- validate sender messages
- if sender message is valid, connect to tcp:65432 receive and parse plaintext length, receive encrypted data, decrypt.

## Web Sharing:

### Sender:
- get share server url from user
- generate x25519 keypair
- generate secret share phrase, or get from user
- generate random salt
- send pub key, salt, hmac(pub key, salt, share phrase) to server
- receive pair code from server
- show pair code to user
- wait for receiver

### Receiver:
- get share server url from user
- gen x25519 keypair
- get secret share phrase from user
- gen random salt
- get pair code from user
- send pair code, pub key, salt, hmac(pub key, salt, share phrase) to server
- wait for server to connect to sender

### Server:
- when post on /ws
    - when receive pub key, salt, hmac from sender on /ws:
        - generate pair code
        - store sender info, ws conn in map[paircode]senderinfo
        - send pair code to sender
        - wait for receiver
    - when receive pair code, pub key, salt, hmac from receiver on /ws:
        - check map for paircode
        - if sender exists, reply with sender info, and send reciever info to sender
        - if not exists, respond with error, dont start ws conn
- when message on ws from sender:
    - if type is binary, forward to receiver
    - if type is text, parse
        - if receiver invalid, cut off receiver, keep sender in map
- when message on ws from receiver:
    - if type is binary, discard
    - if type is text, parse
        - if sender invalid, end conn with receiver, send err to sender?

### Message Types
- Sender Annouce (post)
    - Include senderPubKey, salt, hmac
    - Send in headers as part of post to /ws
- Pair Code (announce response header?)
    - Can we send as http response to /ws if we upgrade to ws?
    - otherwise, send in ws.
    - pair code is random number, or rand alphanum of some length, unique on server.
- Receiver Announce (post)
    - Include receiverPubKey, salt, hmac, pair code
    - Send in headers as part of post to /ws
    - Respond with 404 if pair code / sender not found
    - respond with ws upgrade if found
- Sender / Reciever Info (ws)
    - Send reciever info to sender, sender info to receiver
    - include pubkey, salt, hmac
- InvalidHmacErr (ws -> server)
    - just invalid hmac err
    - sent from sender / receiver to server
    - server will then terminate ws with receiver
- Err (ws server -> sender / receiver)
    - sent when there was an error, like sender or receiver ending transmission early
    - both connections closed
