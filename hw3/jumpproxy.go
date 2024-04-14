package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// generateEncryptionKey takes a passphrase and an optional salt to generate an encryption key using the PBKDF2 algorithm.
// If no salt is provided, it generates a new one and returns both the key and the salt.
func generateEncryptionKey(secret string, optionalSalt []byte) ([]byte, []byte) {
	// Generate a random 8-byte salt if none is provided.
	if optionalSalt == nil {
		optionalSalt = make([]byte, 8)
		rand.Read(optionalSalt)
	}

	// Use PBKDF2 with SHA-256 to derive a 32-byte key from the secret and salt.
	encryptionKey := pbkdf2.Key([]byte(secret), optionalSalt, 1000, 32, sha256.New)
	return encryptionKey, optionalSalt
}

// encodeData takes a passphrase and plaintext, encrypts the data using AES-GCM, and returns the encrypted string with salt and IV.
func encodeData(secret, plainData string) string {
	// Derive key and generate salt if not provided.
	encryptionKey, salt := generateEncryptionKey(secret, nil)

	// Generate a new 12-byte initialization vector for AES-GCM.
	initVector := make([]byte, 12)
	rand.Read(initVector)

	// Create an AES block cipher using the derived key.
	aesBlock, _ := aes.NewCipher(encryptionKey)

	// Set up AES-GCM with the created block.
	gcmCipher, _ := cipher.NewGCM(aesBlock)

	// Encrypt the data using AES-GCM, prefixed by the IV.
	encryptedData := gcmCipher.Seal(nil, initVector, []byte(plainData), nil)

	// Convert the salt, IV, and encrypted data to a hex-encoded string.
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(initVector) + "-" + hex.EncodeToString(encryptedData)
}

// decodeData decrypts the data encrypted by encodeData function.
// It expects a passphrase and a string containing hex-encoded salt, IV, and encrypted data.
func decodeData(secret, encodedText string) string {
	// Extract the hex-encoded salt, IV, and encrypted data from the encoded text.
	components := strings.Split(encodedText, "-")
	decodedSalt, _ := hex.DecodeString(components[0])
	initVector, _ := hex.DecodeString(components[1])
	encryptedData, _ := hex.DecodeString(components[2])

	// Derive the key using the provided passphrase and decoded salt.
	encryptionKey, _ := generateEncryptionKey(secret, decodedSalt)

	// Create an AES block cipher using the derived key.
	aesBlock, _ := aes.NewCipher(encryptionKey)

	// Initialize AES-GCM with the block cipher.
	gcmCipher, _ := cipher.NewGCM(aesBlock)

	// Decrypt the data, expecting no additional data during decryption.
	plainDataBytes, _ := gcmCipher.Open(nil, initVector, encryptedData, nil)

	// Return the decrypted data as a string.
	return string(plainDataBytes)
}

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
			log.Println("ERROR: Failed to read from source: %v", readErr)
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
			log.Println("ERROR: Failed to convert decrypted length: %v", conversionErr)
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
				log.Println("ERROR: Failed to read a full block: %v", blockReadErr)
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
				log.Println("ERROR: Failed to read the final block: %v", finalBlockErr)
				socketSource.Close()
				return
			}
			completeMessage = append(completeMessage, finalBlock[:finalBlockLength]...)
		}

		// Decrypt the complete message
		decryptedMessage := decodeData(passphrase, string(completeMessage[:len(completeMessage)]))
		log.Println("Decrypted message ready for transmission: %d bytes", len(decryptedMessage))

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

// Run Server
func runServer(listenPort string, passphrase string, dstHost string, dstPort string) {
	serviceAddress := dstHost + ":" + dstPort
	log.Printf("pbproxy Server: Preparing to connect to service at %s", serviceAddress)

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
			clientSocket.Close() // Make sure to close the client socket if the service connection fails
			return               // Consider whether to retry the connection or just log and continue
		}

		log.Printf("Connection established with service at %s. Starting data transfer routines.", serviceAddress)
		go transferDecryptedData(clientSocket, serviceSocket, passphrase, true)
		go transferEncryptedData(clientSocket, serviceSocket, passphrase, true)
	}
}

// Run Client
func runClient(passphrase string, dstHost string, dstPort string) {
	serverAddress := dstHost + ":" + dstPort
	log.Printf("pbproxy Client: Attempting to connect to server at %s", serverAddress)

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

func setupLogging() {
	logfile, err := os.OpenFile("logfile.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	// defer logfile.Close()
	log.SetOutput(logfile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile) // Enhanced log formatting
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
