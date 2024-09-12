package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/int32-dev/fastshare/internal/shareservice"
	"github.com/int32-dev/fastshare/internal/ws"
)

type ReceiveCommand struct {
	Code string `short:"c" long:"code" description:"share code provided by sender. If not specified, will prompt for code."`
	File string `short:"f" long:"file" description:"file to write output to. if not specified, prints to stdout"`
}

var receiveCommand ReceiveCommand

func init() {
	parser.AddCommand("receive", "receive share", "receive a share from the sender", &receiveCommand)
	parser.AddCommand("r", "receive share", "receive a share from the sender", &receiveCommand)
}

func (rc *ReceiveCommand) Execute(args []string) error {
	if receiveCommand.Code == "" {
		receiveCommand.Code = getSecretCode()
		fmt.Println("Waiting for sender...")
	}

	var w io.Writer

	printOutput := true
	if receiveCommand.File != "" {
		printOutput = false
		file, err := os.OpenFile(receiveCommand.File, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return err
		}

		defer file.Close()

		w = file
	} else {
		w = bytes.NewBuffer(make([]byte, 0, 4096))
	}

	if options.Web != "" {
		url := options.Web + "/ws"
		if options.Insecure {
			url = "ws://" + url
		} else {
			url = "wss://" + url
		}

		err := ws.Receive(receiveCommand.Code, url, w)
		if err != nil {
			return err
		}
	} else {
		ss, err := shareservice.NewLocalShareService(options.Port, receiveCommand.Code)
		if err != nil {
			return err
		}

		err = ss.Receive(w)
		if err != nil {
			return err
		}
	}

	if printOutput {
		fmt.Println("Received data:")
		fmt.Printf("%s\n", w.(*bytes.Buffer).String())
	}

	return nil
}
