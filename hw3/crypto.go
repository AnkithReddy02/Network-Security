package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
