package helper

import (
	"arch/internal/helper/constants"
	"arch/pkg/apperror"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"time"
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

func GetStringFromFormValue(form *multipart.Form, fieldName string) string {
	if values, ok := form.Value[fieldName]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func GenerateCustomFilename(originalFilename string) string {
	timestamp := time.Now().UnixNano()
	randomStr := generateRandomString(8)
	extension := filepath.Ext(originalFilename)
	filename := fmt.Sprintf("%d_%s%s", timestamp, randomStr, extension)
	return filename
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[num.Int64()]
	}
	return string(result)
}

func ReadFileToBuffer(file *multipart.FileHeader) (*bytes.Buffer, error) {
	f, err := file.Open()
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	return buf, nil
}

func ValidateFileExtension(file *multipart.FileHeader, allowedFiles []string, maxFileSize int64) error {
	if file.Size > maxFileSize {
		return apperror.NewAppError(http.StatusBadRequest, fmt.Sprintf("Ukuran file maksimal %d MB", constants.MAX_SIZE_FILE_APPROVAL_ATTACHMENT))
	}

	mimetype := file.Header.Get("Content-Type")
	isValidFileType := false
	for _, allowedType := range allowedFiles {
		if mimetype == allowedType {
			isValidFileType = true
			break
		}
	}
	if !isValidFileType {
		return apperror.NewAppError(http.StatusBadRequest, "Invalid file type. Only JPEG, PNG, PDF, and MP4 are allowed")
	}

	return nil
}
