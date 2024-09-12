package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/int32-dev/fastshare/internal/ws"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Port int `short:"p" long:"port" default:"8080" description:"port to use for server"`
}

var options Options
var parser = flags.NewParser(&options, flags.Default)
var senderConLock = sync.Mutex{}
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
		for k, s := range senderConnections {
			if time.Since(s.added) > expireTime && !s.getReceiverConnected() {
				err := s.conn.Close(ws.StatusTimeoutError, "timed out waiting for receiver")
				if err != nil {
					fmt.Println(err)
				}

				deleteSenderConnection(k)
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

func deleteSenderConnection(paircode string) {
	senderConLock.Lock()
	defer senderConLock.Unlock()
	conn, ok := senderConnections[paircode]
	if ok {
		delete(senderConnections, paircode)
		conn.conn.Close(websocket.StatusAbnormalClosure, "")
	}
}

type SenderConnection struct {
	info              *ws.ClientInfo
	conn              *websocket.Conn
	m                 sync.Mutex
	receiverConnected bool
	added             time.Time
}

const expireTime = time.Minute * 2

func newSenderConn(info *ws.ClientInfo, conn *websocket.Conn) *SenderConnection {
	return &SenderConnection{
		info:              info,
		conn:              conn,
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
		w.Header().Add(ws.PAIRCODE_HEADER, paircode)
		acceptOptions := &websocket.AcceptOptions{}
		conn, err := websocket.Accept(w, r, acceptOptions)
		if err != nil {
			return err
		}

		senderConnections[paircode] = newSenderConn(clientInfo, conn)
	} else {
		sender, ok := senderConnections[paircode]
		if !ok {
			http.Error(w, "no sender found", http.StatusNotFound)
			return fmt.Errorf("no sender found")
		}

		sender.updateReceiverConnected(true)
		defer sender.updateReceiverConnected(false)
		defer deleteSenderConnection(paircode)

		sender.info.AddToHeaders(w.Header())
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			pump(ctx, sender.conn, conn)
			cancel()
		}()
		pump(ctx, conn, sender.conn)
		cancel()
	}

	return nil
}

func (s *SenderConnection) updateReceiverConnected(connected bool) {
	s.m.Lock()
	defer s.m.Unlock()
	s.receiverConnected = connected
}

func (s *SenderConnection) getReceiverConnected() bool {
	s.m.Lock()
	defer s.m.Unlock()
	return s.receiverConnected
}

func getNewPairCode() string {
	for {
		pairCode := rand.Int31n(10000)
		if _, ok := senderConnections[fmt.Sprintf("%04d", pairCode)]; !ok {
			return fmt.Sprintf("%04d", pairCode)
		}
	}
}

func pump(ctx context.Context, r *websocket.Conn, s *websocket.Conn) {
	for {
		msgType, message, err := s.Read(ctx)
		if err != nil {
			if closeStatus := websocket.CloseStatus(err); closeStatus > 0 {
				err = r.Close(closeStatus, string(message))
				if err != nil {
					fmt.Printf("error closing connection: %v\n", err)
				}

				return
			}

			if errors.Is(err, context.Canceled) {
				fmt.Println("context canceled")
				r.Close(websocket.StatusNormalClosure, "")
			}

			fmt.Println("pump:", err)
			return
		}

		if msgType == websocket.MessageText || msgType == websocket.MessageBinary {
			err := r.Write(ctx, msgType, message)
			if err != nil {
				fmt.Println("error writing:", err)
				return
			}
		}
	}
}
