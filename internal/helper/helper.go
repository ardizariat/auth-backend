package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/spf13/viper"
)

// Crypto is a utility class for encryption and decryption.
type Crypto struct {
	Key string
}

// Encrypt encrypts the given plaintext using AES and the provided key.
func Encrypts(data string, config *viper.Viper) (string, error) {
	key := config.GetString("crypto_secret_key")
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	plaintext := []byte(data)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES and the provided key.
func Decrypts(encrypted string, config *viper.Viper) (string, error) {
	key := config.GetString("crypto_secret_key")
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

const KEY = "secretkey123"

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
