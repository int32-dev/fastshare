package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"
	"golang.org/x/term"
)

type Options struct {
	Port     int    `short:"p" long:"port" default:"65432" description:"port to use for sharing"`
	Web      string `short:"w" long:"web" description:"web server to route share through (required if sending to web client)"`
	Insecure bool   `long:"insecure-ws" description:"use insecure websocket connection (no https)"`
}

var options Options

var parser = flags.NewParser(&options, flags.Default)

func main() {
	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}
}

func getSecretCode() string {
	fmt.Println("Enter share code:")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		os.Exit(1)
	}

	return strings.TrimSpace(string(password))
}
