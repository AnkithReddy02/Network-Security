package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strings"
)

func setupLogging() {
	logfile, err := os.OpenFile("logfile.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	// defer logfile.Close()
	log.SetOutput(logfile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func parseFlagsAndArgs() (string, string, []string) {
	listenPort := flag.String("l", "", "listening port number")
	passphraseFilename := flag.String("k", "", "passphrase input file name")
	flag.Parse()

	if len(flag.Args()) != 2 {
		log.Fatal("Fatal: Two arguments are required: destination host and port number")
	}
	destination := strings.Fields(strings.Join(flag.Args(), " "))

	if *passphraseFilename == "" {
		log.Fatal("Fatal: Passphrase filename cannot be empty")
	}
	return *listenPort, *passphraseFilename, destination
}

func loadPassphrase(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", log.Output(2, "Failed to open the passphrase file: "+filename)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	if scanner.Scan() {
		return scanner.Text(), nil
	}

	return "", log.Output(2, "Error reading passphrase from file")
}
