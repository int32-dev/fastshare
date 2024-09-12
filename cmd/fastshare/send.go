package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/int32-dev/fastshare/internal/sharephrase"
	"github.com/int32-dev/fastshare/internal/shareservice"
	"github.com/int32-dev/fastshare/internal/ws"
)

type SendCommand struct {
	File    string `short:"f" long:"file" description:"file to send"`
	Message string `short:"m" long:"message" description:"message to send"`
	Code    bool   `short:"c" long:"code" description:"enter share code manually. Will be prompted to enter password."`
}

var sendCommand SendCommand

func init() {
	parser.AddCommand("send", "send a message", "send a message or file to the receiver", &sendCommand)
	parser.AddCommand("s", "send a message", "send a message or file to the receiver", &sendCommand)
}

func (s *SendCommand) Execute(args []string) error {
	var discoveryCode string
	if sendCommand.Code {
		discoveryCode = getSecretCode()
		fmt.Println("Waiting for receiver...")
	} else {
		code, err := sharephrase.GetRandomPhrase()
		if err != nil {
			return err
		}

		discoveryCode = code

		fmt.Println("share code:", discoveryCode)
	}

	var r io.Reader
	var totalSize int64

	if sendCommand.Message != "" {
		r = bytes.NewBufferString(sendCommand.Message)
		totalSize = int64(len(sendCommand.Message))
	} else if sendCommand.File != "" {
		file, err := os.OpenFile(sendCommand.File, os.O_RDONLY, 0644)
		if err != nil {
			return err
		}

		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			return err
		}

		totalSize = info.Size()
		r = file
	} else {
		fmt.Println("Missing message or file to send.")
		os.Exit(1)
	}

	if options.Web != "" {
		return ws.Send(discoveryCode, options.Web, r, totalSize)
	}

	ss, err := shareservice.NewLocalShareService(options.Port, discoveryCode)
	if err != nil {
		return err
	}

	err = ss.Send(r, totalSize)
	if err != nil {
		return err
	}

	fmt.Println("Message sent. Exiting.")

	return nil
}
