package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"
	"golang.org/x/term"
)

type Options struct {
	Port int `short:"p" long:"port" default:"65432" description:"port to use for sharing"`
}

var options Options

var parser = flags.NewParser(&options, flags.Default)

func main() {
	_, err := parser.Parse()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func genKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func getSecretCode() string {
	fmt.Println("Enter share code:")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return strings.TrimSpace(string(password))
}
