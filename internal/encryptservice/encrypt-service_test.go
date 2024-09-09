package encryptservice

import (
	"bytes"
	"crypto/rand"
	"testing"
)

const TEST_STRING = "This is my string... Does it match?"
const TEST_DISCOVER_PHRASE = "bluepenguin23"

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)

	data := []byte(TEST_STRING)

	encryptService, err := NewGcmService(key, TEST_DISCOVER_PHRASE)
	if err != nil {
		t.Error(err)
	}

	decryptService, err := NewGcmService(key, TEST_DISCOVER_PHRASE)
	if err != nil {
		t.Error(err)
	}

	for i := range 100 {
		cipherText, err := encryptService.encryptGCM(data)
		if err != nil {
			t.Error(err)
		}

		plainText, err := decryptService.decryptGCM(cipherText)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(plainText, data) {
			t.Error("bytes not equal, round", i)
		}
	}
}

func TestHmac(t *testing.T) {
	data := Hmac512([]byte(TEST_STRING), []byte(TEST_DISCOVER_PHRASE))

	data2 := Hmac512([]byte(TEST_STRING), []byte(TEST_DISCOVER_PHRASE))

	if !bytes.Equal(data, data2) {
		t.Error("hmac values not equal")
	}
}
