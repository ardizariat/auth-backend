package usecase

import (
	"arch/internal/gateway/producer"
	"arch/internal/model"
	"arch/internal/repository"
	"arch/pkg/appjwt"
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type UserUseCase struct {
	AuthDatabase   model.AuthDatabase
	IthubDatabase  model.IthubDatabase
	Config         *viper.Viper
	Logger         *logrus.Logger
	Redis          *redis.Client
	Jwt            *appjwt.JwtWrapper
	ProducerRMQ    *producer.RabbitMQProducer
	AwsS3          *s3.Client
	UserRepository *repository.UserRepository
}

func NewUserUseCase(
	authDatabase model.AuthDatabase,
	ithubDatabase model.IthubDatabase,
	redis *redis.Client,
	config *viper.Viper,
	logger *logrus.Logger,
	jwt *appjwt.JwtWrapper,
	producerRMQ *producer.RabbitMQProducer,
	awsS3 *s3.Client,
	userRepository *repository.UserRepository,
) *UserUseCase {
	return &UserUseCase{
		AuthDatabase:   authDatabase,
		IthubDatabase:  ithubDatabase,
		Config:         config,
		Logger:         logger,
		Redis:          redis,
		Jwt:            jwt,
		ProducerRMQ:    producerRMQ,
		AwsS3:          awsS3,
		UserRepository: userRepository,
	}
}

func (u *UserUseCase) GetAllFirebaseTokenByUserIds(ctx context.Context, userIds []string) ([]model.DataFirebaseToken, error) {
	if len(userIds) < 1 {
		return nil, errors.New("user ids must not be empty")
	}
	tx := (*u.AuthDatabase).WithContext(ctx)
	result, err := u.UserRepository.GetAllFirebaseTokenByUserIds(tx, userIds)
	if err != nil {
		return nil, err
	}
	return result, nil
}
