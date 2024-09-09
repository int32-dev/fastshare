package encryptservice

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
)

type GcmService struct {
	key            []byte
	discoverPhrase string
	gcm            cipher.AEAD
	nonce          []byte
}

func NewGcmService(key []byte, discoverPhrase string) (*GcmService, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	return &GcmService{
		key:            key,
		discoverPhrase: discoverPhrase,
		gcm:            gcm,
		nonce:          nonce,
	}, nil
}

func (s *GcmService) incrementNonce() {
	for i, b := range s.nonce {
		if b == 255 {
			s.nonce[i] = 0
		} else {
			s.nonce[i] += 1
			break
		}
	}
}

func (s *GcmService) encryptGCM(data []byte, out []byte) ([]byte, error) {
	cipherText := s.gcm.Seal(out[:0], s.nonce, data, []byte(s.discoverPhrase))

	s.incrementNonce()

	return cipherText, nil
}

func (s *GcmService) decryptGCM(ciphertext []byte, buf []byte) ([]byte, error) {
	plaintext, err := s.gcm.Open(buf[:0], s.nonce, ciphertext, []byte(s.discoverPhrase))
	if err != nil {
		return nil, err
	}

	s.incrementNonce()

	return plaintext, nil
}

const CHUNK_SIZE = 4096

type BufferedEncryptor struct {
	gcmService *GcmService
	r          io.Reader
	buf        *bytes.Buffer
}

func (be *BufferedEncryptor) Read(buf []byte) (int, error) {
	lastPacket := false

	n, err := io.CopyN(be.buf, be.r, CHUNK_SIZE)
	if err != nil && !errors.Is(err, io.EOF) {
		return int(n), fmt.Errorf("failed to read data: %w", err)
	}

	if n < CHUNK_SIZE {
		lastPacket = true
	}

	ciphertext, err := be.gcmService.encryptGCM(be.buf.Bytes(), buf)
	if err != nil {
		return int(n), fmt.Errorf("failed to encrypt: %w", err)
	}

	be.buf.Reset()

	read := len(ciphertext)

	if lastPacket {
		return read, io.EOF
	}

	return read, nil
}

func (s *GcmService) GetBufferEncryptor(r io.Reader) *BufferedEncryptor {
	return &BufferedEncryptor{
		gcmService: s,
		r:          r,
		buf:        bytes.NewBuffer(make([]byte, 0, CHUNK_SIZE)),
	}
}

type BufferedDecryptor struct {
	gcmService         *GcmService
	r                  io.Reader
	buf                *bytes.Buffer
	encryptedChunkSize int
}

func (s *GcmService) NewBufferedDecryptor(r io.Reader) *BufferedDecryptor {
	chunkSize := CHUNK_SIZE + s.gcm.Overhead()
	return &BufferedDecryptor{
		gcmService:         s,
		r:                  r,
		buf:                bytes.NewBuffer(make([]byte, 0, chunkSize)),
		encryptedChunkSize: chunkSize,
	}
}

func (bd *BufferedDecryptor) Read(buf []byte) (int, error) {
	n, err := io.CopyN(bd.buf, bd.r, int64(bd.encryptedChunkSize))
	if err != nil && !errors.Is(err, io.EOF) {
		return int(n), err
	}

	plainText, err := bd.gcmService.decryptGCM(bd.buf.Bytes(), buf)
	if err != nil {
		return 0, err
	}

	bd.buf.Reset()

	if n < int64(bd.encryptedChunkSize) {
		return len(plainText), io.EOF
	}

	return len(plainText), nil
}

func Hmac512(data []byte, key []byte) []byte {
	hash := hmac.New(sha512.New, key)
	return hash.Sum(data)
}

func GetKey(priKey *ecdh.PrivateKey, pubKey *ecdh.PublicKey) ([]byte, error) {
	key, err := priKey.ECDH(pubKey)
	return key, err
}
