package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/int32-dev/fastshare/internal/shareservice"
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

	ss, err := shareservice.NewLocalShareService(options.Port, receiveCommand.Code)
	if err != nil {
		return err
	}

	if receiveCommand.File != "" {
		file, err := os.OpenFile(receiveCommand.File, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return err
		}

		defer file.Close()

		err = ss.Receive(file)
		if err != nil {
			return err
		}
	} else {
		dat := bytes.NewBuffer(make([]byte, 0, 4096))

		err = ss.Receive(dat)
		if err != nil {
			return err
		}

		fmt.Println("Received data:")
		fmt.Printf("%s\n", dat.String())
	}

	return nil
}
