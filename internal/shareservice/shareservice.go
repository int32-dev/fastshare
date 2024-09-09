package shareservice

import (
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/int32-dev/fastshare/internal/encryptservice"
)

const CHUNK_SIZE = 4096

type ShareService struct {
	addr            net.Addr
	port            int
	onClientConnect func()
}

func NewShareService(addr net.Addr, port int, onClientConnect func()) *ShareService {
	return &ShareService{
		addr:            addr,
		port:            port,
		onClientConnect: onClientConnect,
	}
}

func getIP(addr net.Addr) string {
	vals := strings.SplitN(addr.String(), ":", 2)
	return vals[0]
}

func (s *ShareService) Send(r io.Reader, es *encryptservice.GcmService) error {
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

		if getIP(s.addr) != getIP(conn.RemoteAddr()) {
			conn.Close()
			continue
		}

		break
	}

	if s.onClientConnect != nil {
		s.onClientConnect()
	}

	defer conn.Close()

	r2 := es.GetBufferEncryptor(r)
	_, err = io.Copy(conn, r2)

	return err
}

func (s *ShareService) Receive(w io.Writer, es *encryptservice.GcmService) error {
	conn, err := net.Dial("tcp", getIP(s.addr)+":"+strconv.Itoa(s.port))
	if err != nil {
		return err
	}

	defer conn.Close()

	r := es.NewBufferedDecryptor(conn)

	_, err = io.Copy(w, r)
	return err
}
