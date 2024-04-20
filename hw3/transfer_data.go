package main

import (
    "encoding/binary"
    "io"
    "log"
    "net"
    "os"
)

// transferDecryptedData manages the transfer of encrypted data from one socket to another after decrypting it.
// It continuously reads from socketSource, decrypts the content using a provided passphrase, and writes the decrypted content to socketDestination if isServer is true, or to standard output if false.
func transferDecryptedData(socketSource net.Conn, socketDestination net.Conn, passphrase string, isServer bool) {
    log.Println("INFO: Starting decryption and data transfer...")
    for {
        // First read the length of the encrypted message
        lengthBuffer := make([]byte, 4) // Assuming length is stored in 4 bytes
        log.Println("INFO: Reading encrypted message length...")
        _, err := io.ReadFull(socketSource, lengthBuffer)
        if err != nil {
            log.Printf("ERROR: Failed to read from source: %v", err)
            socketSource.Close()
            return
        }

        // Decode the length
        encryptedLength := binary.BigEndian.Uint32(lengthBuffer)
        log.Printf("INFO: Encrypted message length: %d bytes", encryptedLength)

        // Read the encrypted message based on the decoded length
        encryptedMessage := make([]byte, encryptedLength)
        log.Printf("INFO: Reading encrypted message of %d bytes...", encryptedLength)
        _, err = io.ReadFull(socketSource, encryptedMessage)
        if err != nil {
            log.Printf("ERROR: Failed to read encrypted message: %v", err)
            socketSource.Close()
            return
        }

        // Decrypt the message
        decryptedMessage := decodeData(passphrase, string(encryptedMessage))
        log.Printf("INFO: Decrypted message ready for transmission: %d bytes", len(decryptedMessage))

        // Convert decrypted message to byte array for transmission or display
        decryptedMessageBytes := []byte(decryptedMessage)

        // Write to the destination socket if it's server mode, otherwise write to standard output
        if isServer {
            log.Println("INFO: Writing decrypted message to destination socket...")
            _, writeErr := socketDestination.Write(decryptedMessageBytes)
            if writeErr != nil {
                log.Printf("ERROR: Failed to write decrypted message to destination: %v", writeErr)
                return
            }
        } else {
            log.Println("INFO: Writing decrypted message to stdout...")
            _, writeErr := os.Stdout.Write(decryptedMessageBytes)
            if writeErr != nil {
                log.Printf("ERROR: Failed to write decrypted message to stdout: %v", writeErr)
                return
            }
        }
    }
}

func transferEncryptedData(sourceSocket net.Conn, destinationSocket net.Conn, encryptionKey string, isServerMode bool) {
    var bytesRead int
    var readErr error
    dataBuffer := make([]byte, 1024) // Buffer to store data read from the source

    log.Println("INFO: Beginning data transfer...")
    for {
        if isServerMode {
            // In server mode, read data from the destination socket (client)
            log.Println("INFO: Server mode active, reading from destination socket...")
            bytesRead, readErr = destinationSocket.Read(dataBuffer)
        } else {
            // In client mode, read data from standard input (stdin)
            log.Println("INFO: Client mode active, reading from stdin...")
            bytesRead, readErr = os.Stdin.Read(dataBuffer)
        }

        if readErr != nil {
            if readErr == io.EOF {
                // Handle end of file gracefully
                log.Println("INFO: No more data to read, EOF reached.")
                break // Exit the loop if we are done reading data
            }
            log.Printf("ERROR: Read failure, closing sockets: %v", readErr)
            sourceSocket.Close()
            if isServerMode {
                destinationSocket.Close()
            }
            return
        }

        if bytesRead == 0 {
            log.Println("INFO: Read 0 bytes, skipping...")
            continue // Skip empty reads
        }

        log.Printf("INFO: Read %d bytes, encrypting...", bytesRead)
        // Encrypt the data using the provided encryption key.
        encryptedData := encodeData(encryptionKey, string(dataBuffer[:bytesRead]))
        encryptedBytes := []byte(encryptedData)

        // Prepare and send the length of the encrypted data
        lengthBuffer := make([]byte, 4)
        binary.BigEndian.PutUint32(lengthBuffer, uint32(len(encryptedBytes)))
        if _, err := sourceSocket.Write(lengthBuffer); err != nil {
            log.Printf("ERROR: Failed to write data length: %v", err)
            return
        }

        // Send the encrypted data
        if _, err := sourceSocket.Write(encryptedBytes); err != nil {
            log.Printf("ERROR: Failed to write encrypted data: %v", err)
            return
        }

        log.Printf("INFO: Successfully sent %d bytes of encrypted data.", len(encryptedBytes))
    }
    log.Println("INFO: Data transfer completed.")
}
