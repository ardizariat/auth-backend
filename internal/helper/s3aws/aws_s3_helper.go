package s3_aws

import (
	"context"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func GetObjectFromS3(ctx context.Context, s3Client *s3.Client, bucketName, objectKey string) (*v4.PresignedHTTPRequest, error) {
	presignClient := s3.NewPresignClient(s3Client)
	input := &s3.GetObjectInput{
		Bucket: &bucketName,
		Key:    &objectKey,
	}
	// Set your expiration time here
	expFile := 1 * time.Minute
	options := s3.WithPresignExpires(expFile)
	// Generate a presigned URL for getting an object
	response, err := presignClient.PresignGetObject(ctx, input, options)
	if err != nil {
		return nil, err
	}

	return response, nil
}
