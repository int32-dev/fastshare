package encryptservice

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

const TEST_STRING = "This is my string... Does it match?"
const TEST_DISCOVER_PHRASE = "bluepenguin23"

func TestEncryptDecrypt(t *testing.T) {
	ecdh1, err := GenerateEcdhKeypair()
	if err != nil {
		t.Error(err)
	}

	ecdh2, err := GenerateEcdhKeypair()
	if err != nil {
		t.Error(err)
	}

	data := []byte(TEST_STRING)

	encryptService, err := NewGcmService(ecdh1, ecdh2.PublicKey(), TEST_DISCOVER_PHRASE)
	if err != nil {
		t.Error(err)
	}

	decryptService, err := NewGcmService(ecdh2, ecdh1.PublicKey(), TEST_DISCOVER_PHRASE)
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
	salt := make([]byte, 16)
	rand.Read(salt)

	s1 := NewHmacService(TEST_DISCOVER_PHRASE)
	s2 := NewHmacService(TEST_DISCOVER_PHRASE)

	sig1 := s1.Sign([]byte(TEST_STRING), salt)
	sig2 := s2.Sign([]byte(TEST_STRING), salt)

	sig12 := s1.Sign([]byte(TEST_STRING), salt)

	if !bytes.Equal(sig1, sig2) {
		t.Error("hmac values not equal")
	}

	if !bytes.Equal(sig1, sig12) {
		t.Error("hmac values not equal")
	}

	if !s2.Verify([]byte(TEST_STRING), sig1, salt) {
		t.Errorf("hmac verification failed %v %v %v", TEST_STRING, salt, sig1)
	}
}

func TestCreateP256(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		t.Error(err)
	}

	t.Log("length pubkey: ", len(key.PublicKey().Bytes()))
	t.Log("pubkey: ", base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()))
}
