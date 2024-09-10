package shareservice

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/int32-dev/fastshare/internal/discoverservice"
	"github.com/int32-dev/fastshare/internal/encryptservice"
)

const CHUNK_SIZE = 4096

type LocalShareService struct {
	port      int
	shareCode string
	key       *ecdh.PrivateKey
}

func NewLocalShareService(port int, shareCode string) (*LocalShareService, error) {
	key, err := encryptservice.GenerateEcdhKeypair()
	if err != nil {
		return nil, err
	}

	return &LocalShareService{
		port:      port,
		shareCode: shareCode,
		key:       key,
	}, nil
}

func getIP(addr net.Addr) string {
	vals := strings.SplitN(addr.String(), ":", 2)
	return vals[0]
}

func (s *LocalShareService) Send(r io.Reader, totalSize int64) error {
	ds, err := discoverservice.NewDiscoveryService(s.key.PublicKey(), s.shareCode, s.port)
	if err != nil {
		return err
	}

	defer ds.Close()

	response, err := ds.ListenForReceiver()
	if err != nil {
		return err
	}

	fmt.Println("Receiver found at", response.Addr)

	aeskey, err := encryptservice.GetKey(s.key, response.Key)
	if err != nil {
		return err
	}

	es, err := encryptservice.NewGcmService(aeskey, s.shareCode)
	if err != nil {
		return err
	}

	l, err := net.Listen("tcp", ":"+strconv.Itoa(s.port))
	if err != nil {
		return err
	}

	defer l.Close()

	var conn net.Conn

	for {
		conn, err = l.Accept()
		if err != nil {
			return err
		}

		if getIP(response.Addr) != getIP(conn.RemoteAddr()) {
			conn.Close()
			continue
		}

		break
	}

	ds.Close()

	defer conn.Close()

	sizeBytes := make([]byte, 8)
	binary.PutVarint(sizeBytes, totalSize)

	_, err = conn.Write(sizeBytes)
	if err != nil {
		return err
	}

	err = es.Encrypt(r, conn, totalSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}

func (s *LocalShareService) Receive(w io.Writer) error {
	ds, err := discoverservice.NewDiscoveryService(s.key.PublicKey(), s.shareCode, s.port)
	if err != nil {
		return err
	}

	defer ds.Close()

	response, err := ds.DiscoverSender()
	if err != nil {
		return err
	}

	fmt.Println("Sender found at", response.Addr)
	ds.Close()

	aeskey, err := encryptservice.GetKey(s.key, response.Key)
	if err != nil {
		return err
	}

	es, err := encryptservice.NewGcmService(aeskey, s.shareCode)
	if err != nil {
		return err
	}

	conn, err := net.Dial("tcp", getIP(response.Addr)+":"+strconv.Itoa(s.port))
	if err != nil {
		return err
	}

	defer conn.Close()

	sizeBytes := make([]byte, 8)
	_, err = io.ReadFull(conn, sizeBytes)
	if err != nil {
		return err
	}

	totalSize, err := binary.ReadVarint(bytes.NewReader(sizeBytes))
	if err != nil {
		return err
	}

	err = es.Decrypt(conn, w, totalSize)
	if err != nil {
		return err
	}

	return nil
}
