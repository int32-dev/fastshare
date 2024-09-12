package discoverservice

import (
	"bytes"
	"crypto/ecdh"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/int32-dev/fastshare/internal/encryptservice"
)

type DiscoverResponse struct {
	Addr      net.Addr
	PublicKey *ecdh.PublicKey
}

type DiscoverService struct {
	discoveryPhrase string
	port            int
	sock            net.PacketConn
	message         []byte
	stop            chan struct{}
	once            *sync.Once
	hmacService     *encryptservice.HmacService
}

const ECDH_SIZE = 32
const HMAC_SIZE = 64

func NewDiscoveryService(pubKey *ecdh.PublicKey, discoveryPhrase string, port int) (*DiscoverService, error) {
	sock, err := net.ListenPacket("udp4", ":"+strconv.Itoa((port)))
	if err != nil {
		return nil, err
	}

	hmacService := encryptservice.NewHmacService(discoveryPhrase)
	salt, err := encryptservice.GenreateSalt()
	if err != nil {
		return nil, err
	}

	message := make([]byte, 0, ECDH_SIZE+encryptservice.SALT_SIZE+HMAC_SIZE)
	pubkeyBytes := pubKey.Bytes()
	mac := hmacService.Sign(pubkeyBytes, salt)
	message = append(message, pubkeyBytes...)
	message = append(message, salt...)
	message = append(message, mac...)

	return &DiscoverService{
		discoveryPhrase: discoveryPhrase,
		port:            port,
		sock:            sock,
		message:         message,
		hmacService:     hmacService,
		stop:            make(chan struct{}),
		once:            &sync.Once{},
	}, nil
}

var ErrInvalidHmac = fmt.Errorf("invalid hmac")
var ErrMessageTooShort = fmt.Errorf("message too short")

func (s *DiscoverService) ParseMessage(message []byte) (*ecdh.PublicKey, error) {
	if len(message) < ECDH_SIZE+encryptservice.SALT_SIZE+HMAC_SIZE {
		return nil, ErrMessageTooShort
	}

	pubKeyBytes := message[:ECDH_SIZE]
	salt := message[ECDH_SIZE : ECDH_SIZE+encryptservice.SALT_SIZE]
	sig := message[ECDH_SIZE+encryptservice.SALT_SIZE:]

	pubkey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	if !s.hmacService.Verify(pubkey.Bytes(), sig, salt) {
		return nil, ErrInvalidHmac
	}

	return pubkey, nil
}

func (s *DiscoverService) listenForMessage() (*DiscoverResponse, error) {
	buf := make([]byte, 1024)

	for {
		n, addr, err := s.sock.ReadFrom(buf)
		if err != nil {
			return nil, err
		}

		pkey, err := s.ParseMessage(buf[:n])
		if err != nil {
			continue
		}

		if bytes.Equal(pkey.Bytes(), s.message[:ECDH_SIZE]) {
			// ignore self
			continue
		}

		return &DiscoverResponse{
			Addr:      addr,
			PublicKey: pkey,
		}, nil
	}
}

func (s *DiscoverService) sendPings(addrs []*net.UDPAddr) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			for _, addr := range addrs {
				s.sock.WriteTo(s.message, addr)
			}
		case <-s.stop:
			return
		}
	}
}

func (s *DiscoverService) getBroadcastAddresses() ([]*net.UDPAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var broadcastAddresses []net.IP

	for _, iface := range interfaces {
		if iface.Flags&net.FlagBroadcast == 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, err
			}

			var bip []byte

			isIp4 := ip.To4() != nil
			if isIp4 {
				bip = []byte(ip.To4())
			} else {
				bip = []byte(ip.To16())
			}

			if bip == nil {
				continue
			}

			bmask := []byte(ipNet.Mask)

			if len(bip) != len(bmask) {
				continue
			}

			bdcst := make([]byte, len(bip))

			for i := range bip {
				bdcst[i] = bip[i] | ^bmask[i]
			}

			broadcastAddresses = append(broadcastAddresses, net.IP(bdcst))
		}
	}

	addrs := make([]*net.UDPAddr, 0, len(broadcastAddresses))
	for _, ip := range broadcastAddresses {
		addr := &net.UDPAddr{
			IP:   ip,
			Port: s.port,
		}
		addrs = append(addrs, addr)
	}

	return addrs, nil
}

func (s *DiscoverService) DiscoverSender() (*DiscoverResponse, error) {
	addrs, err := s.getBroadcastAddresses()
	if err != nil {
		return nil, err
	}

	go s.sendPings(addrs)

	response, err := s.listenForMessage()
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (s *DiscoverService) ListenForReceiver() (*DiscoverResponse, error) {
	response, err := s.listenForMessage()
	if err != nil {
		return nil, err
	}

	go s.sendPings([]*net.UDPAddr{response.Addr.(*net.UDPAddr)})

	return response, nil
}

func (s *DiscoverService) Close() {
	s.once.Do(func() {
		close(s.stop)
		s.sock.Close()
	})
}
