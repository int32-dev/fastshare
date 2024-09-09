package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/int32-dev/fastshare/internal/discoverservice"
	"github.com/int32-dev/fastshare/internal/encryptservice"
	"github.com/int32-dev/fastshare/internal/shareservice"
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
		discoveryCode = discoverservice.GetDiscoveryPhrase()
		fmt.Println("share code: ", discoveryCode)
	}

	key, err := genKey()
	if err != nil {
		return err
	}

	ds, err := discoverservice.NewDiscoveryService(key.PublicKey(), discoveryCode, options.Port)
	if err != nil {
		return err
	}

	defer ds.Close()

	response, err := ds.ListenForReceiver()
	if err != nil {
		return err
	}

	fmt.Println("Receiver found at", response.Addr)

	aeskey, err := encryptservice.GetKey(key, response.Key)
	if err != nil {
		return err
	}

	es, err := encryptservice.NewGcmService(aeskey, discoveryCode)
	if err != nil {
		return err
	}

	ss := shareservice.NewShareService(response.Addr, options.Port, func() {
		ds.Close()
	})

	if sendCommand.Message != "" {
		dat := bytes.NewBufferString(sendCommand.Message)
		err = ss.Send(dat, es)
		if err != nil {
			return err
		}

		fmt.Println("Message sent. Exiting.")
	} else if sendCommand.File != "" {
		file, err := os.OpenFile(sendCommand.File, os.O_RDONLY, 0644)
		if err != nil {
			return err
		}

		defer file.Close()

		err = ss.Send(file, es)
		if err != nil {
			return err
		}

		fmt.Println("File sent. Exiting.")
	} else {
		fmt.Println("Missing message or file to send.")
		os.Exit(1)
	}

	return nil
}
