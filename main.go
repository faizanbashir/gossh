package main

import (
	"os"
	"log"
	"flag"
	"bytes"
	"os/exec"
	"strings"
	"io/ioutil"
	"encoding/json"
	"golang.org/x/crypto/ssh"
)

var host string
var port string
var username string
var command string
var keyPath string
var keyPass string

type Data struct {
	Commands []string `json:"commands"`
}

func init() {
	flag.StringVar(&host, "host", "", "SSH hostname or IP")
	flag.StringVar(&port, "port", "22", "SSH Port")
	flag.StringVar(&username, "username", "", "SSH username")
	flag.StringVar(&command, "command", "", "Command to be executed")
	flag.StringVar(&keyPath, "key-path", "", "For example: ~/.ssh/id_rsa")
	flag.StringVar(&keyPass, "key-pass", "", "Password for private key optional")
	flag.Parse()
	if host == "" || username == "" || keyPath == "" {
		flag.PrintDefaults()
		log.Fatalf("Input not correct")
	}
}

func readPubKey(file string) ssh.AuthMethod {
	var key ssh.Signer
	var err error
	var b []byte
	b, err = ioutil.ReadFile(file)
	if err != nil {
		log.Fatalf("Failed to read pulic key: %s", err)
	}
	if !strings.Contains(string(b), "ENCRYPTED") {
		key, err = ssh.ParsePrivateKey(b)
		if err != nil {
			log.Fatalf("Failed to parse public key: %s", err)
		}
	} else {
		key, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(keyPass))
		if err != nil {
			log.Fatalf("Failed to parse password-protected key: %s", err)
		}
	}
	return ssh.PublicKeys(key)
}

func connectToServer(config *ssh.ClientConfig) (*ssh.Client) {
	client, err := ssh.Dial("tcp", strings.Join([]string{host, ":", port}, ""), config)
	if err != nil {
		log.Fatalf("%s: %s\n %s", "Failed to log into the server", host, err)
	}
	log.Printf("Connection successfully established with host: %s", host)
	return client
}

func runCommands(client *ssh.Client) {
	content, err := ioutil.ReadFile("./commands.json")
	if err != nil {
		log.Fatalf("Error when opening file: %s", err)
	}

	var payload Data
	err = json.Unmarshal(content, &payload)
	if err != nil {
		log.Fatalf("Error getting commands: %s", err)
	}

	// log.Printf("%v", payload.Commands)

	for _, element := range payload.Commands {
		command := strings.ToLower(element)
		// Executing one command per session
		session, err := client.NewSession()
		if err != nil {
			log.Fatalf("Failed to create session: %s", err)
		}

		defer session.Close()

		var b bytes.Buffer
		session.Stdout = &b
		err = session.Run(command)
		if err != nil {
			log.Printf("You used an invalid command")
			err = nil
		}
		log.Printf("Executing command: %s", command)
		log.Printf("Response from server:\n%s", b.String())
	}
	//clear the terminal and display conn closed
	clear := exec.Command("clear")
	clear.Stdout = os.Stdout
	clear.Run()
	log.Printf("\nDisconnected from Host %s", host)
}

func main() {
	conf := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			readPubKey(keyPath),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client := connectToServer(conf)
	runCommands(client)
}