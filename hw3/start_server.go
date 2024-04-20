package main

import (
    "log"
    "net"
    "os"
)

// Run Server
func runServer(listenPort string, passphrase string, dstHost string, dstPort string) {
    serviceAddress := dstHost + ":" + dstPort
    log.Printf("JumpProxy Server: Preparing to connect to service at %s", serviceAddress)

    listen, err := net.Listen("tcp", ":"+listenPort)
    if err != nil {
        log.Printf("ERROR: Failed to listen on port %s: %v", listenPort, err)
        os.Exit(1)
    }
    defer listen.Close()
    log.Printf("Server is now listening on port %s", listenPort)

    for {
        log.Println("Server main thread waiting for incoming client connections...")

        clientSocket, err := listen.Accept()
        if err != nil {
            log.Printf("ERROR: Failed to accept incoming client connection: %v", err)
            return
        }
        log.Printf("Client connected, job is assigned to a goroutine. Client address: %s", clientSocket.RemoteAddr())

        // Connecting to the destination service
        serviceSocket, err := net.Dial("tcp", serviceAddress)
        if err != nil {
            log.Printf("ERROR: Failed to establish connection with service at %s: %v", serviceAddress, err)
            clientSocket.Close() // Close the connection
            return
        }

        log.Printf("Connection established with service at %s. Starting data transfer routines.", serviceAddress)
        go transferDecryptedData(clientSocket, serviceSocket, passphrase, true)
        go transferEncryptedData(clientSocket, serviceSocket, passphrase, true)
    }
}
