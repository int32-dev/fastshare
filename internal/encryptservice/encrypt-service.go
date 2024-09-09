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
	"time"
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

const CHUNK_SIZE = 8192 * 2

func (g *GcmService) Encrypt(r io.Reader, w io.Writer, totalPlaintextSize int64) error {
	start := time.Now()
	updated := time.Time{}
	sent := int64(0)
	encSent := int64(0)
	sentSinceLastUpdate := int64(0)

	buf := make([]byte, CHUNK_SIZE)
	for {
		n, err := io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("failed to read data: %w", err)
		}

		ciphertext, err := g.encryptGCM(buf[:n])
		if err != nil {
			return fmt.Errorf("failed to encrypt: %w", err)
		}

		if err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}

		_, err = w.Write(ciphertext)
		if err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}

		sent += int64(n)
		encSent += int64(len(ciphertext))
		sentSinceLastUpdate += int64(n)

		if totalPlaintextSize > 0 && time.Since(updated) > time.Second {
			progress := float64(sent) / float64(totalPlaintextSize) * 100
			fmt.Printf("\r%.2f%%", progress)
			fmt.Printf(" %.2f MB/s", float64(sentSinceLastUpdate)/1024/1024/time.Since(updated).Seconds())

			updated = time.Now()
			sentSinceLastUpdate = 0
		}

		if n < CHUNK_SIZE {
			fmt.Printf("\r100.00%%")
			fmt.Printf(" %.2f MB/s\n", float64(encSent)/1024/1024/time.Since(start).Seconds())

			return io.EOF
		}
	}
}

func (g *GcmService) Decrypt(r io.Reader, w io.Writer, totalPlaintextSize int64) error {
	buf := make([]byte, CHUNK_SIZE+g.gcm.Overhead())

	start := time.Now()
	updated := time.Time{}
	received := int64(0)
	receivedPlain := int64(0)
	receivedSinceLastUpdate := int64(0)

	for {
		n, err := io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("failed to read data: %w", err)
		}

		plaintext, err := g.decryptGCM(buf[:n])
		if err != nil {
			return fmt.Errorf("failed to decrypt: %w", err)
		}

		_, err = w.Write(plaintext)
		if err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}

		received += int64(n)
		receivedPlain += int64(len(plaintext))
		receivedSinceLastUpdate += int64(n)

		if time.Since(updated) > time.Second {
			progress := float64(receivedPlain) / float64(totalPlaintextSize) * 100
			fmt.Printf("\r%.2f%% %.2f MB/s", progress, float64(receivedSinceLastUpdate)/1024/1024/time.Since(updated).Seconds())
			updated = time.Now()
			receivedSinceLastUpdate = 0
		}

		if receivedPlain >= totalPlaintextSize {
			fmt.Printf("\r100%% %.2f MB/s\n", float64(received)/1024/1024/time.Since(start).Seconds())
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
