package main

import (
	"os"
	"fmt"
	"log"
	"flag"
	"strings"
	"io/ioutil"
	"encoding/json"
)

var hostsFile string
var username string
var keyPath string
var keyPass string
var password string
var outputFile string

type Host struct {
	IP          string `json:"ip"`
	User        string `json:"user"`
	AuthKeyPath string `json:"auth_key_path,omitempty"`
	Password    string `json:"password,omitempty"`
	AuthKeyPass string `json:"auth_key_pass,omitempty"`
}

func init() {
	flag.StringVar(&hostsFile, "hosts-file", "", "SSH hostname or IP")
	flag.StringVar(&username, "username", "", "SSH username")
	flag.StringVar(&keyPath, "key-path", "", "For example: ~/.ssh/id_rsa")
	flag.StringVar(&keyPass, "key-pass", "", "Password for private key optional")
	flag.StringVar(&password, "password", "", "Password for the server")
	flag.StringVar(&outputFile, "output-file", "hosts.json", "Output file name")
	flag.Parse()
	if hostsFile == "" || username == "" || ( keyPath == "" && password == "" ) {
		flag.PrintDefaults()
		log.Fatalf("Input not correct")
	}
}

func readHostsFromFile(filename string) ([]Host) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("Could not read file %s", err)
		os.Exit(1)
	}

	lines := strings.Split(string(content), "\n")

	var hosts []Host

	for _, ip := range lines {
		if ip == "" {
			continue
		}
		hosts = append(hosts, Host{IP: ip, User: username, AuthKeyPath: keyPath})
	}

	return hosts
}

func readHostsFromJSON(filename string) ([]Host) {
	lines, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Could not read file: %s", err)
	}

	var hosts []Host

	err = json.Unmarshal(lines, &hosts)
	if err != nil {
		log.Fatalf("Could not read JSON: %s", err)
	}

	return hosts
}

func main() {
	hosts := readHostsFromFile(hostsFile)

	objs, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", objs)

	err = ioutil.WriteFile(outputFile, objs, 0644)
	if err != nil {
		panic(err)
	}

	hostIPs := readHostsFromJSON(outputFile)
	fmt.Printf("%s", hostIPs)
}