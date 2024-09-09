package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/int32-dev/fastshare/internal/discoverservice"
	"github.com/int32-dev/fastshare/internal/encryptservice"
	"github.com/int32-dev/fastshare/internal/shareservice"
)

type ReceiveCommand struct {
	Code string `short:"c" long:"code" description:"secret share code provided by sender"`
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

	key, err := genKey()
	if err != nil {
		return err
	}

	ds, err := discoverservice.NewDiscoveryService(key.PublicKey(), receiveCommand.Code, options.Port)
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

	aeskey, err := encryptservice.GetKey(key, response.Key)
	if err != nil {
		return err
	}

	es, err := encryptservice.NewGcmService(aeskey, receiveCommand.Code)
	if err != nil {
		return err
	}

	ss := shareservice.NewShareService(response.Addr, options.Port, nil)

	if receiveCommand.File != "" {
		file, err := os.OpenFile(receiveCommand.File, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return err
		}

		defer file.Close()

		err = ss.Receive(file, es)
		if err != nil {
			return err
		}

		fmt.Println("received file, exiting.")
	} else {
		dat := bytes.NewBuffer(make([]byte, 0, 4096))

		err = ss.Receive(dat, es)
		if err != nil {
			return err
		}

		fmt.Println("Received data:")
		fmt.Printf("%s\n", dat.String())
	}

	return nil
}
