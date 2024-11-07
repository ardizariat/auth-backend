package constants

const (
	AUTH_JWT                          = "AUTH_JWT"
	REFRESH_TOKEN                     = "REFRESH_TOKEN"
	AWS_S3_PUT_OBJECT                 = "s3_put_object"
	AWS_S3_DELETE                     = "aws_s3_delete"
	EMAIL_VERIFY                      = "email_verify"
	MAX_SIZE_FILE_APPROVAL_ATTACHMENT = 10 * 1024 * 1024 // 100 MB
)

var (
	ALLOWED_FILE_UPLOAD_APPROVAL_ATTACHMENT = []string{
		// "image/jpeg",
		// "image/png",
		"application/pdf",
		// "video/mp4",
		// "application/vnd.ms-excel",
		// "application/msword",
		// "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		// "audio/mpeg",
		// "application/vnd.ms-powerpoint",
		// "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		// "text/plain",
		// "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	}
)
