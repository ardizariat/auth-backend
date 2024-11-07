package config

import (
	"context"

	configS3 "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func NewAwsS3(viperConfig *viper.Viper, log *logrus.Logger) *s3.Client {
	AWS_ACCESS_KEY := viperConfig.GetString("aws.s3.access_key")
	AWS_SECRET_KEY := viperConfig.GetString("aws.s3.secret_key")
	AWS_DEFAULT_REGION := viperConfig.GetString("aws.s3.region")
	// Initialize AWS configuration with hardcoded credentials
	cfg, err := configS3.LoadDefaultConfig(context.TODO(),
		configS3.WithRegion(AWS_DEFAULT_REGION),
		configS3.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(AWS_ACCESS_KEY, AWS_SECRET_KEY, "")),
	)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// Create S3 client
	s3Client := s3.NewFromConfig(cfg)

	return s3Client
}
