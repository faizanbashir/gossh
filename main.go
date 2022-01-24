package main

import (
	"os"
	"log"
	"flag"
	"bytes"
	"strings"
	"io/ioutil"
	"golang.org/x/crypto/ssh"
)

var host string
var port string
var username string
var command string
var keyPath string
var keyPass string

func init() {
	flag.StringVar(&host, "host", "", "SSH hostname or IP")
	flag.StringVar(&port, "port", "", "SSH Port")
	flag.StringVar(&username, "username", "", "SSH username")
	flag.StringVar(&command, "command", "", "Command to be executed")
	flag.StringVar(&keyPath, "key-path", "", "For example: ~/.ssh/id_rsa")
	flag.StringVar(&keyPass, "key-pass", "", "Password for private key optional")
	flag.Parse()
	if host == "" || port == "" || command == "" || username == "" || keyPath == "" {
		flag.PrintDefaults()
		os.Exit(2)
	}
}

func readPubKey(file string) ssh.AuthMethod {
	var key ssh.Signer
	var err error
	var b []byte
	var keyPass string = "elk"
	b, err = ioutil.ReadFile(file)
	mustExec(err, "Failed to read pulic key")
	if !strings.Contains(string(b), "ENCRYPTED") {
		key, err = ssh.ParsePrivateKey(b)
		mustExec(err, "Failed to parse public key")
	} else {
		key, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(keyPass))
		mustExec(err, "Failed to parse password-protected key")
	}
	return ssh.PublicKeys(key)
}

func main() {
	conf := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			readPubKey(keyPath),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", strings.Join([]string{host, ":", port}, ""), conf)
	mustExec(err, "Failed to create SSH server!")
	session, err := client.NewSession()
	mustExec(err, "Failed to create SSH session!")
	defer session.Close()
	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(command)
	mustExec(err, "Failed to run command over SSH!")
	log.Printf("%s: %s", command, b.String())
}

func mustExec(err error, msg string) {
	if err != nil {
		log.Fatalf("%s:\n  %s", msg, err)
	}
}