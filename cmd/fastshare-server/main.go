package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/int32-dev/fastshare/internal/ws"
	"github.com/jessevdk/go-flags"
)

var upgrader = websocket.Upgrader{}

type Options struct {
	Port int `short:"p" long:"port" default:"8080" description:"port to use for server"`
}

var options Options
var parser = flags.NewParser(&options, flags.Default)
var senderConnections = make(map[string]*SenderConnection)

func main() {
	_, err := parser.Parse()
	if err != nil {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", errorMiddleware(handleWsConnect))

	go monitorConnections()

	err = http.ListenAndServe(":"+strconv.Itoa(options.Port), mux)
	if err != nil {
		fmt.Println("error:", err)
	}
}

func monitorConnections() {
	for range time.Tick(time.Second * 5) {
		fmt.Println("connections:", len(senderConnections))
		for k, s := range senderConnections {
			if time.Since(s.added) > expireTime && !s.receiverConnected {
				err := s.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "timed out waiting for receiver"), time.Now().Add(time.Second*3))
				if err != nil {
					fmt.Println(err)
				}

				s.close()
				delete(senderConnections, k)
				fmt.Println("sender expired:", k)
				continue
			}
		}
	}
}

func errorMiddleware(next func(w http.ResponseWriter, r *http.Request) error) func(w http.ResponseWriter, r *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := next(w, r)
		if err != nil {
			fmt.Println("error:", err)
		}
	})
}

type SenderConnection struct {
	info              *ws.ClientInfo
	conn              *websocket.Conn
	once              *sync.Once
	receiverConnected bool
	added             time.Time
}

func (s *SenderConnection) close() {
	s.once.Do(func() {
		s.conn.Close()
	})
}

const expireTime = time.Minute * 2

func newSenderConn(info *ws.ClientInfo, conn *websocket.Conn) *SenderConnection {
	return &SenderConnection{
		info:              info,
		conn:              conn,
		once:              &sync.Once{},
		receiverConnected: false,
		added:             time.Now(),
	}
}

func handleWsConnect(w http.ResponseWriter, r *http.Request) error {
	clientInfo, err := ws.NewClientInfoFromHeaders(r.Header)
	if err != nil {
		http.Error(w, "error parsing headers", http.StatusBadRequest)
		return err
	}

	paircode := r.Header.Get(ws.PAIRCODE_HEADER)

	if paircode == "" {
		paircode = getNewPairCode()
		header := http.Header{}
		header.Add(ws.PAIRCODE_HEADER, paircode)

		conn, err := upgrader.Upgrade(w, r, header)
		if err != nil {
			return err
		}

		conn.SetCloseHandler(func(code int, text string) error {
			sender, ok := senderConnections[paircode]
			if !ok {
				return nil
			}

			sender.close()
			delete(senderConnections, paircode)
			return nil
		})

		senderConnections[paircode] = newSenderConn(clientInfo, conn)
	} else {
		sender, ok := senderConnections[paircode]
		if !ok {
			http.Error(w, "no sender found", http.StatusNotFound)
			return fmt.Errorf("no sender found")
		}

		sender.receiverConnected = true

		header := http.Header{}
		sender.info.AddToHeaders(header)
		conn, err := upgrader.Upgrade(w, r, header)
		if err != nil {
			return err
		}

		defer conn.Close()
		defer sender.close()
		defer delete(senderConnections, paircode)
		go pump(sender.conn, conn)
		pump(conn, sender.conn)
	}

	return nil
}

func getNewPairCode() string {
	for {
		pairCode := rand.Int31n(10000)
		if _, ok := senderConnections[fmt.Sprintf("%04d", pairCode)]; !ok {
			return fmt.Sprintf("%04d", pairCode)
		}
	}
}

func pump(r *websocket.Conn, s *websocket.Conn) {
	for {
		msgType, message, err := s.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				r.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*3))
			}

			if websocket.IsCloseError(err, websocket.CloseAbnormalClosure) {
				r.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseAbnormalClosure, ""), time.Now().Add(time.Second*3))
			}

			return
		}

		if msgType == websocket.TextMessage || msgType == websocket.BinaryMessage {
			err = r.WriteMessage(msgType, message)
			if err != nil {
				return
			}
		}

		if msgType == websocket.CloseMessage {
			r.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*3))
			return
		}
	}
}
