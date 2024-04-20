package main

import (
    "log"
    "net"
    "os"
)

// Run Client
func runClient(passphrase string, dstHost string, dstPort string) {
    serverAddress := dstHost + ":" + dstPort
    log.Printf("JumpProxy Client: Attempting to connect to server at %s", serverAddress)

    socketSource, err := net.Dial("tcp", serverAddress)
    if err != nil {
        log.Printf("ERROR: Failed to establish a connection with %s: %v", serverAddress, err)
        os.Exit(1) // Exit with status 1 indicating a general error
    }
    log.Printf("Connected successfully to server at %s", serverAddress)

    // Starting goroutine to transfer data
    go transferEncryptedData(socketSource, nil, passphrase, false)

    // Transfer decrypted data in the main thread
    transferDecryptedData(socketSource, nil, passphrase, false)
}
