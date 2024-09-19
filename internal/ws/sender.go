package ws

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/coder/websocket"
	"github.com/int32-dev/fastshare/internal/encryptservice"
)

type WsSenderHandler struct {
	conn *websocket.Conn
	gs   *encryptservice.GcmService
}

func NewWsSendHandler(shareCode string, addr string) (*WsSenderHandler, error) {
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

	query := url.Values{}
	info.AddToQuery(query)

	uri, err := url.Parse(addr + "?" + query.Encode())
	if err != nil {
		return nil, err
	}

	conn, response, err := websocket.Dial(context.Background(), uri.String(), nil)
	if err != nil {
		if response != nil {
			fmt.Println(response.Status)
			io.Copy(os.Stdout, response.Body)
		}

		return nil, err
	}

	var pairCode string
	err = ReadAndParseTextMessage(conn, "pairCode", &pairCode)
	if err != nil {
		conn.Close(websocket.StatusProtocolError, "")
		return nil, err
	}

	fmt.Printf("share code: %s%s\n", shareCode, pairCode)
	fmt.Println("waiting for receiver...")

	receiverInfo := &ClientInfo{}
	err = ReadAndParseTextMessage(conn, "receiverInfo", receiverInfo)
	if err != nil {
		conn.Close(websocket.StatusProtocolError, "")

		if status := websocket.CloseStatus(err); status == StatusTimeoutError {
			return nil, fmt.Errorf("timed out waiting for receiver")
		}

		return nil, err
	}

	if !hmac.Verify(receiverInfo.PubKey, receiverInfo.Hmac, receiverInfo.Salt) {
		conn.Close(websocket.StatusProtocolError, "invalid hmac")
		return nil, fmt.Errorf("invalid hmac")
	}

	pubKey, err := encryptservice.ParsePublicKey(receiverInfo.PubKey)
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

func (s *WsSenderHandler) Write(p []byte) (int, error) {
	err := s.conn.Write(context.Background(), websocket.MessageBinary, p)
	return len(p), err
}

func Send(shareCode string, url string, r io.Reader, size int64) error {
	s, err := NewWsSendHandler(shareCode, url)
	if err != nil {
		return err
	}

	defer s.conn.Close(websocket.StatusProtocolError, "")

	err = s.writeSizeMessage(size)
	if err != nil {
		return err
	}

	s.conn.CloseRead(context.Background())

	err = s.gs.Encrypt(r, s, size)
	if err != nil {
		return err
	}

	err = s.conn.Close(websocket.StatusNormalClosure, "")
	return err
}

func (s *WsSenderHandler) writeSizeMessage(size int64) error {
	msg, err := GetJsonMessageBytes("size", size)
	if err != nil {
		return err
	}

	return s.conn.Write(context.Background(), websocket.MessageText, msg)
}
