package ws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

const PUBKEY_HEADER = "X-FS-PUBKEY"
const SALT_HEADER = "X-FS-SALT"
const HMAC_HEADER = "X-FS-HMAC"
const PAIRCODE_HEADER = "X-FS-PAIRCODE"

type ClientInfo struct {
	PubKey []byte
	Salt   []byte
	Hmac   []byte
}

type SenderConnection struct {
	Info              *ClientInfo
	Conn              *websocket.Conn
	done              chan struct{}
	once              *sync.Once
	ReceiverConnected bool
}

func (s *SenderConnection) Close() {
	s.once.Do(func() {
		close(s.done)
	})
}

func NewSenderConn(info *ClientInfo, conn *websocket.Conn) *SenderConnection {
	return &SenderConnection{
		Info:              info,
		Conn:              conn,
		done:              make(chan struct{}),
		once:              &sync.Once{},
		ReceiverConnected: false,
	}
}

type ErrorMessage struct {
	Error string
}

func NewClientInfoFromHeaders(header http.Header) (*ClientInfo, error) {
	return parseHeaders(header)
}

func (info *ClientInfo) AddToHeaders(header http.Header) {
	addHeaders(header, info)
}

func addHeaders(header http.Header, info *ClientInfo) {
	header.Add(PUBKEY_HEADER, base64.StdEncoding.EncodeToString(info.PubKey))
	header.Add(SALT_HEADER, base64.StdEncoding.EncodeToString(info.Salt))
	header.Add(HMAC_HEADER, base64.StdEncoding.EncodeToString(info.Hmac))
}

func parseHeaders(header http.Header) (*ClientInfo, error) {
	pubkey := header.Get(PUBKEY_HEADER)
	salt := header.Get(SALT_HEADER)
	hmac := header.Get(HMAC_HEADER)

	if pubkey == "" || salt == "" || hmac == "" {
		return nil, fmt.Errorf("missing headers")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pubkey: %w", err)
	}

	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	hmacBytes, err := base64.StdEncoding.DecodeString(hmac)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hmac: %w", err)
	}

	clientInfo := &ClientInfo{
		PubKey: pubKeyBytes,
		Salt:   saltBytes,
		Hmac:   hmacBytes,
	}

	return clientInfo, nil
}

func GetJsonMessageBytes(messageRoute string, data interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	message := make([]byte, 0, len(jsonData)+len(messageRoute)+1)

	message = append(message, []byte(messageRoute)...)
	message = append(message, '\n')
	message = append(message, jsonData...)
	return message, nil
}

func ParseTextMessage(message []byte) (string, []byte, error) {
	if len(message) == 0 {
		return "", nil, fmt.Errorf("empty message")
	}

	messageParts := bytes.SplitN(message, []byte("\n"), 2)

	if len(messageParts) != 2 {
		return "", nil, fmt.Errorf("invalid message format")
	}

	return string(messageParts[0]), messageParts[1], nil
}
