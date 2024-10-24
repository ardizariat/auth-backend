package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

const KEY = "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47"

func Encrypt(plainText string) (string, error) {
	// Create a new AES cipher block with the key
	block, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		return "", err
	}

	// Convert the plain text to bytes
	plainTextBytes := []byte(plainText)

	// Generate a new AES-GCM block
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce (number used once)
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the plain text using AES-GCM
	cipherText := aesGCM.Seal(nonce, nonce, plainTextBytes, nil)

	// Encode the cipher text to a base64 string
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func Decrypt(cipherText string) (string, error) {
	// Decode the base64 encoded cipher text
	cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	// Create a new AES cipher block with the key
	block, err := aes.NewCipher([]byte(KEY))
	if err != nil {
		return "", err
	}

	// Generate a new AES-GCM block
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract the nonce from the cipher text
	nonceSize := aesGCM.NonceSize()
	nonce, cipherTextBytes := cipherTextBytes[:nonceSize], cipherTextBytes[nonceSize:]

	// Decrypt the cipher text using AES-GCM
	plainTextBytes, err := aesGCM.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	// Convert the plain text bytes to a string
	return string(plainTextBytes), nil
}
