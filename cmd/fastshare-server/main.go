package main

import (
	"fmt"
	"net/http"
	"strconv"
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

func main() {
	_, err := parser.Parse()
	if err != nil {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", errorMiddleware(handleWsConnect))

	err = http.ListenAndServe(":"+strconv.Itoa(options.Port), mux)
	if err != nil {
		fmt.Println("error:", err)
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

var senderConnections = make(map[string]*ws.SenderConnection)

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

			sender.Close()
			delete(senderConnections, paircode)
			return nil
		})

		senderConnections[paircode] = ws.NewSenderConn(clientInfo, conn)
	} else {
		sender, ok := senderConnections[paircode]
		if !ok {
			http.Error(w, "no sender found", http.StatusNotFound)
			return fmt.Errorf("no sender found")
		}

		header := http.Header{}
		sender.Info.AddToHeaders(header)
		conn, err := upgrader.Upgrade(w, r, header)
		if err != nil {
			return err
		}

		defer conn.Close()
		defer sender.Close()
		go pump(sender.Conn, conn)
		pump(conn, sender.Conn)
	}

	return nil
}

func getNewPairCode() string {
	return "1234"
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
