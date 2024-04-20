package main

import (
    "log"
)

func main() {
    setupLogging()

    // Parse flags and arguments
    listenPort, passphraseFilename, destination := parseFlagsAndArgs()

    // Load passphrase from file
    passphrase, err := loadPassphrase(passphraseFilename)
    if err != nil {
        log.Printf("Error: %v\n", err)
        return
    }
    log.Printf("Passphrase loaded successfully: %s\n", passphrase)

    // Start the server or client based on the listen port
    if listenPort == "" {
        log.Printf("Starting client targeting host %s at port %s\n", destination[0], destination[1])
        runClient(passphrase, destination[0], destination[1])
    } else {
        log.Printf("Starting server on port %s\n", listenPort)
        runServer(listenPort, passphrase, destination[0], destination[1])
    }
}
