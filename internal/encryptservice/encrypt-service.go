package encryptservice

import (
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

func (s *GcmService) encryptGCM(data []byte) ([]byte, error) {
	cipherText := s.gcm.Seal(data[:0], s.nonce, data, []byte(s.discoverPhrase))

	s.incrementNonce()

	return cipherText, nil
}

func (s *GcmService) decryptGCM(ciphertext []byte) ([]byte, error) {
	plaintext, err := s.gcm.Open(ciphertext[:0], s.nonce, ciphertext, []byte(s.discoverPhrase))
	if err != nil {
		return nil, err
	}

	s.incrementNonce()

	return plaintext, nil
}

const CHUNK_SIZE = 4096

func (g *GcmService) Encrypt(r io.Reader, w io.Writer) error {
	buf := make([]byte, CHUNK_SIZE)
	for {
		n, err := io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("failed to read data: %w", err)
		}

		if n == 0 {
			return nil
		}

		ciphertext, err := g.encryptGCM(buf[:n])
		if err != nil {
			return fmt.Errorf("failed to encrypt: %w", err)
		}

		_, err = w.Write(ciphertext)
		if err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}

		if n < CHUNK_SIZE {
			return io.EOF
		}
	}
}

func (g *GcmService) Decrypt(r io.Reader, w io.Writer) error {
	buf := make([]byte, CHUNK_SIZE+g.gcm.Overhead())
	for {
		n, err := io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("failed to read data: %w", err)
		}

		if n == 0 {
			return nil
		}

		plaintext, err := g.decryptGCM(buf[:n])
		if err != nil {
			return fmt.Errorf("failed to decrypt: %w", err)
		}

		_, err = w.Write(plaintext)
		if err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}

		if n < CHUNK_SIZE {
			return io.EOF
		}
	}
}

func Hmac512(data []byte, key []byte) []byte {
	hash := hmac.New(sha512.New, key)
	return hash.Sum(data)
}

func GetKey(priKey *ecdh.PrivateKey, pubKey *ecdh.PublicKey) ([]byte, error) {
	key, err := priKey.ECDH(pubKey)
	return key, err
}
