package ws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/coder/websocket"
)

const PubkeyQuery = "pubkey"
const SaltQuery = "salt"
const HmacQuery = "hmac"
const PaircodeQuery = "paircode"
const StatusTimeoutError = websocket.StatusCode(3000)

type ClientInfo struct {
	PubKey []byte
	Salt   []byte
	Hmac   []byte
}

type ErrorMessage struct {
	Error string
}

func ReadAndParseTextMessage(conn *websocket.Conn, route string, v interface{}) error {
	msgType, message, err := conn.Read(context.Background())
	if err != nil {
		return err
	}

	if msgType != websocket.MessageText {
		return fmt.Errorf("unexpected message type: %v", msgType)
	}

	messageRoute, data, err := ParseTextMessage(message)
	if err != nil {
		return err
	}

	if messageRoute != route {
		return fmt.Errorf("unexpected message route: %s", messageRoute)
	}

	err = json.Unmarshal(data, v)
	if err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

func NewClientInfoFromQueryString(query url.Values) (*ClientInfo, error) {
	return parseHeaders(query)
}

func (info *ClientInfo) AddToQuery(query url.Values) {
	addQueryParams(query, info)
}

func addQueryParams(query url.Values, info *ClientInfo) {
	query.Add(PubkeyQuery, base64.StdEncoding.EncodeToString(info.PubKey))
	query.Add(SaltQuery, base64.StdEncoding.EncodeToString(info.Salt))
	query.Add(HmacQuery, base64.StdEncoding.EncodeToString(info.Hmac))
}

func parseHeaders(query url.Values) (*ClientInfo, error) {
	pubkey := query.Get(PubkeyQuery)
	salt := query.Get(SaltQuery)
	hmac := query.Get(HmacQuery)

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
