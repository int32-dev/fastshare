package ws

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/coder/websocket"
	"github.com/int32-dev/fastshare/internal/encryptservice"
)

const PAIR_CODE_LEN = 4

type WsReceiveHandler struct {
	conn     *websocket.Conn
	gs       *encryptservice.GcmService
	byteChan chan []byte
}

func NewWsReceiveHandler(sharePairCode string, url string) (*WsReceiveHandler, error) {
	codeLen := len(sharePairCode)

	if len(sharePairCode) < PAIR_CODE_LEN {
		return nil, fmt.Errorf("pair code too short")
	}

	shareCode := sharePairCode[:codeLen-PAIR_CODE_LEN]
	pairCode := sharePairCode[codeLen-PAIR_CODE_LEN:]

	hmacService := encryptservice.NewHmacService(shareCode)

	keyPair, err := encryptservice.GenerateEcdhKeypair()
	if err != nil {
		return nil, err
	}

	salt, err := encryptservice.GenreateSalt()
	if err != nil {
		return nil, err
	}

	info := &ClientInfo{
		PubKey: keyPair.PublicKey().Bytes(),
		Salt:   salt,
		Hmac:   hmacService.Sign(keyPair.PublicKey().Bytes(), salt),
	}

	header := http.Header{}
	info.AddToHeaders(header)
	header.Add(PAIRCODE_HEADER, pairCode)
	dialOpts := &websocket.DialOptions{
		HTTPHeader: header,
	}
	conn, response, err := websocket.Dial(context.TODO(), url, dialOpts)
	if err != nil {
		if response != nil {
			defer response.Body.Close()
			fmt.Println(response.Status)
			io.Copy(os.Stdout, response.Body)
		}

		return nil, err
	}

	if response.Body != nil {
		response.Body.Close()
	}

	senderInfo, err := NewClientInfoFromHeaders(response.Header)
	if err != nil {
		return nil, err
	}

	if !hmacService.Verify(senderInfo.PubKey, senderInfo.Hmac, senderInfo.Salt) {
		conn.Close(websocket.StatusProtocolError, "invalid hmac")
		return nil, fmt.Errorf("invalid hmac")
	}

	pubKey, err := ecdh.X25519().NewPublicKey(senderInfo.PubKey)
	if err != nil {
		return nil, err
	}

	fmt.Println("Sending receiver info")

	msg, err := GetJsonMessageBytes("receiverInfo", info)
	if err != nil {
		return nil, err
	}

	err = conn.Write(context.TODO(), websocket.MessageText, msg)
	if err != nil {
		return nil, err
	}

	gcmServ, err := encryptservice.NewGcmService(keyPair, pubKey, shareCode)
	if err != nil {
		return nil, err
	}

	return &WsReceiveHandler{
		conn:     conn,
		gs:       gcmServ,
		byteChan: make(chan []byte, 1),
	}, nil
}

func (h *WsReceiveHandler) Read(p []byte) (int, error) {
	data, ok := <-h.byteChan
	if !ok {
		return 0, io.EOF
	}

	copy(p, data)
	return len(data), nil
}

func Receive(sharePairCode string, url string, w io.Writer) error {
	r, err := NewWsReceiveHandler(sharePairCode, url)
	if err != nil {
		return err
	}

	defer r.conn.Close(websocket.StatusProtocolError, "")

	fmt.Println("waiting for sender response")

	size, err := r.getSizeMessage()
	if err != nil {
		return err
	}

	go func() {
		for {
			msgType, data, err := r.conn.Read(context.TODO())
			if err != nil {
				if status := websocket.CloseStatus(err); status > -1 {
					if status != websocket.StatusNormalClosure {
						fmt.Println("read pump:", err)
					}
				}

				close(r.byteChan)
				return
			}

			if msgType != websocket.MessageBinary {
				fmt.Println("unexpected message type")
				continue
			}

			r.byteChan <- data
		}
	}()

	err = r.gs.Decrypt(r, w, size)

	if err != nil {
		return err
	}

	r.conn.Close(websocket.StatusNormalClosure, "")

	return nil
}

func (h *WsReceiveHandler) getSizeMessage() (int64, error) {
	var size int64
	err := ReadAndParseTextMessage(h.conn, "size", &size)

	return size, err
}
