package main

import (
	"log"
	"net"
	"os"
	"strconv"
)

// transferDecryptedData manages the transfer of encrypted data from one socket to another after decrypting it.
// It continuously reads from socketSource, decrypts the content using a provided passphrase, and writes the decrypted content to socketDestination if isServer is true, or to standard output if false.
func transferDecryptedData(socketSource net.Conn, socketDestination net.Conn, passphrase string, isServer bool) {
	// Continuously process incoming data
	for {
		// Create a buffer to hold data from the source socket
		dataBuffer := make([]byte, 1024)

		// Read data from the source socket into the buffer
		_, readErr := socketSource.Read(dataBuffer)
		if readErr != nil {
			log.Printf("ERROR: Failed to read from source: %v", readErr)
			// Close the source socket on error and exit the loop
			socketSource.Close()
			return
		}

		// Find the first null byte which indicates the end of the meaningful data
		endOfData := 0
		for endOfData = 0; endOfData < 1024; endOfData++ {
			if dataBuffer[endOfData] == 0 {
				break
			}
		}

		// Decrypt the length of the total message using the passphrase
		decryptedLengthStr := decodeData(passphrase, string(dataBuffer[:endOfData]))
		decryptedLength, conversionErr := strconv.Atoi(decryptedLengthStr)
		if conversionErr != nil {
			log.Printf("ERROR: Failed to convert decrypted length: %v", conversionErr)
			return
		}

		// Prepare to receive the full message based on the decrypted length
		var completeMessage []byte

		// Calculate number of full and partial blocks to read
		fullBlocks := decryptedLength / 1024
		finalBlockLength := decryptedLength % 1024

		// Read the full blocks
		for i := 0; i < fullBlocks; i++ {
			block := make([]byte, 1024)
			bytesRead, blockReadErr := socketSource.Read(block)
			if blockReadErr != nil {
				log.Printf("ERROR: Failed to read a full block: %v", blockReadErr)
				socketSource.Close()
				return
			}
			completeMessage = append(completeMessage, block[:bytesRead]...)
		}

		// Read the final partial block, if any
		if finalBlockLength != 0 {
			finalBlock := make([]byte, 1024)
			_, finalBlockErr := socketSource.Read(finalBlock)
			if finalBlockErr != nil {
				log.Printf("ERROR: Failed to read the final block: %v", finalBlockErr)
				socketSource.Close()
				return
			}
			completeMessage = append(completeMessage, finalBlock[:finalBlockLength]...)
		}

		// Decrypt the complete message
		decryptedMessage := decodeData(passphrase, string(completeMessage[:len(completeMessage)]))
		log.Printf("Decrypted message ready for transmission: %d bytes", len(decryptedMessage))

		// Convert decrypted message to byte array for transmission or display
		decryptedMessageBytes := []byte(decryptedMessage)

		// Write to the destination socket if it's server mode, otherwise write to standard output
		if isServer {
			_, writeErr := socketDestination.Write(decryptedMessageBytes)
			if writeErr != nil {
				log.Printf("ERROR: Failed to write decrypted message to destination: %v", writeErr)
				return
			}
		} else {
			_, writeErr := os.Stdout.Write(decryptedMessageBytes)
			if writeErr != nil {
				log.Printf("ERROR: Failed to write decrypted message to stdout: %v", writeErr)
				return
			}
		}
	}
}

// transferData handles the encryption and transfer of data between two sockets.
func transferEncryptedData(sourceSocket net.Conn, destinationSocket net.Conn, encryptionKey string, isServerMode bool) {
	for {
		var bytesRead int
		dataBuffer := make([]byte, 1024) // Buffer to store data read from source.

		if isServerMode {
			// In server mode, read data from the destination socket (client).
			readCount, readError := destinationSocket.Read(dataBuffer)
			bytesRead = readCount
			if readError != nil {
				// If read fails, log the error and close both sockets.
				log.Printf("ERROR: Read failure from client, closing sockets: %v", readError)
				sourceSocket.Close()
				destinationSocket.Close()
				return
			}
			log.Printf("Server read %d bytes from destination socket.", bytesRead)
		} else {
			// In client mode, read data from standard input (stdin).
			readCount, readError := os.Stdin.Read(dataBuffer)
			bytesRead = readCount
			if readError != nil {
				// If read from stdin fails, log the error and stop the function.
				log.Printf("ERROR: Reading from stdin failed: %v", readError)
				return
			}
			log.Printf("Client read %d bytes from stdin.", bytesRead)
		}

		// Encrypt the data using the provided encryption key.
		encryptedData := encodeData(encryptionKey, string(dataBuffer[:bytesRead]))
		encryptedBytes := []byte(encryptedData)
		log.Printf("Data encrypted, preparing to send %d bytes.", len(encryptedBytes))

		// Determine how many full 1024-byte blocks and any remainder need to be sent.
		blocksToSend := len(encryptedBytes) / 1024
		bytesRemainder := len(encryptedBytes) % 1024

		// Encrypt and prepare the length of encrypted data for transmission.
		encryptedLengthStr := strconv.Itoa(len(encryptedBytes))
		encryptedLengthData := encodeData(encryptionKey, encryptedLengthStr)
		lengthBuffer := make([]byte, 1024)
		lengthBuffer = []byte(encryptedLengthData[:len(encryptedLengthData)]) // Prepare length buffer.

		// Prepare the initial buffer with the length of encrypted data.
		prepBuffer := make([]byte, 1024)
		prepBuffer = append(lengthBuffer, prepBuffer[len(lengthBuffer):]...)
		_, err := sourceSocket.Write(prepBuffer)

		if err != nil {
			log.Println("ERROR: Writing length Failed")
			return
		}

		log.Printf("Sent the length of the encrypted data (%d bytes).", len(lengthBuffer))

		// Send each full block of encrypted data.
		for i := 0; i < blocksToSend; i++ {
			dataBlock := encryptedBytes[i*1024 : (i+1)*1024]
			_, err := sourceSocket.Write(dataBlock)

			if err != nil {
				log.Println("ERROR: Writing Block failed")
				return
			}

			log.Printf("Sent block %d of size 1024 bytes.", i+1)
		}

		// Send any remaining bytes in the final block.
		if bytesRemainder != 0 {
			remainderBuffer := make([]byte, 1024)
			remainderBuffer = append(encryptedBytes[blocksToSend*1024:], remainderBuffer[len(encryptedBytes)-blocksToSend*1024:]...)
			_, err := sourceSocket.Write(remainderBuffer)

			if err != nil {
				log.Println("ERROR: Writing Remaining Bytes Failed")
				return
			}

			log.Printf("Sent final block of size %d bytes.", bytesRemainder)
		}
	}
}
