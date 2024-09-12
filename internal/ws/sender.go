package ws

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
	"github.com/int32-dev/fastshare/internal/encryptservice"
)

type WsSenderHandler struct {
	conn *websocket.Conn
	gs   *encryptservice.GcmService
}

func NewWsSendHandler(shareCode string, url string) (*WsSenderHandler, error) {
	keyPair, err := encryptservice.GenerateEcdhKeypair()
	if err != nil {
		return nil, err
	}

	salt, err := encryptservice.GenreateSalt()
	if err != nil {
		return nil, err
	}

	hmac := encryptservice.NewHmacService(shareCode)
	info := &ClientInfo{
		PubKey: keyPair.PublicKey().Bytes(),
		Salt:   salt,
		Hmac:   hmac.Sign(keyPair.PublicKey().Bytes(), salt),
	}

	header := http.Header{}

	info.AddToHeaders(header)

	conn, response, err := websocket.DefaultDialer.Dial("ws://"+url+"/ws", header)
	if err != nil {
		if response != nil {
			defer response.Body.Close()
			fmt.Println(response.Status)
			io.Copy(os.Stdout, response.Body)
		}

		return nil, err
	}

	response.Body.Close()

	pairCode := response.Header.Get(PAIRCODE_HEADER)
	fmt.Printf("share code: %s%s\n", shareCode, pairCode)
	fmt.Println("waiting for receiver...")

	msgType, message, err := conn.ReadMessage()
	if err != nil {
		if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			return nil, fmt.Errorf("%s", err.(*websocket.CloseError).Text)
		}

		return nil, fmt.Errorf("error: %w", err)
	}

	if msgType != websocket.TextMessage {
		return nil, fmt.Errorf("unexpected message type")
	}

	route, data, err := ParseTextMessage(message)
	if err != nil {
		return nil, err
	}

	if route != "receiverInfo" {
		return nil, fmt.Errorf("unexpected message")
	}

	receiverInfo := &ClientInfo{}
	err = json.Unmarshal(data, receiverInfo)
	if err != nil {
		return nil, err
	}

	if !hmac.Verify(receiverInfo.PubKey, receiverInfo.Hmac, receiverInfo.Salt) {
		return nil, fmt.Errorf("invalid hmac")
	}

	pubKey, err := ecdh.X25519().NewPublicKey(receiverInfo.PubKey)
	if err != nil {
		return nil, err
	}

	fmt.Println("receiver connected")

	gcmService, err := encryptservice.NewGcmService(keyPair, pubKey, shareCode)
	if err != nil {
		return nil, err
	}

	return &WsSenderHandler{
		conn: conn,
		gs:   gcmService,
	}, nil
}

func (s *WsSenderHandler) Close() {
	s.conn.Close()
}

func (s *WsSenderHandler) Write(p []byte) (int, error) {
	err := s.conn.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

func Send(shareCode string, url string, r io.Reader, size int64) error {
	s, err := NewWsSendHandler(shareCode, url)
	if err != nil {
		return err
	}

	defer s.Close()

	err = s.writeSizeMessage(size)
	if err != nil {
		return err
	}

	err = s.gs.Encrypt(r, s, size)
	if err != nil {
		return err
	}

	return s.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*3))
}

func (s *WsSenderHandler) writeSizeMessage(size int64) error {
	msg, err := GetJsonMessageBytes("size", size)
	if err != nil {
		return err
	}

	return s.conn.WriteMessage(websocket.TextMessage, msg)
}
