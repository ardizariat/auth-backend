package helper

import (
	"arch/internal/helper/constants"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"mime/multipart"
	"path/filepath"
	"strconv"
	"time"
)

func GetStringFromFormValue(form *multipart.Form, fieldName string) string {
	if values, ok := form.Value[fieldName]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func GetInt64FromFormValue(form *multipart.Form, fieldName string) int64 {
	if values, ok := form.Value[fieldName]; ok && len(values) > 0 {
		value, err := strconv.Atoi(values[0])
		if err != nil {
			return 0
		}
		return int64(value)
	}
	return 0
}

func GetBoolFromFormValue(form *multipart.Form, fieldName string) bool {
	if values, ok := form.Value[fieldName]; ok && len(values) > 0 {
		return values[0] == "true"
	}
	return false
}

func ParseDateFromFormValue(form *multipart.Form, fieldName string) time.Time {
	dateStr := GetStringFromFormValue(form, fieldName)
	if dateStr == "" {
		return time.Time{}
	}
	// Customize date parsing as needed
	date, _ := time.Parse(time.DateOnly, dateStr)
	return date
}

func ReadFileToBuffer(file *multipart.FileHeader) (*bytes.Buffer, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return nil, err
	}

	return buf, nil
}

func ValidateFileExtension(file *multipart.FileHeader, allowedFiles []string, maxFileSize int64) error {
	if file.Size > maxFileSize {
		size := math.Floor(constants.MAX_SIZE_FILE_APPROVAL_ATTACHMENT / 1024 / 1024)
		return fmt.Errorf("ukuran file maksimal %d MB", int(size))
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
		return errors.New("jenis file yang diupload tidak diperbolehkan")
	}

	return nil
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
