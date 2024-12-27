package usecase

import (
	"arch/internal/entity"
	"arch/internal/gateway/producer"
	"arch/internal/helper"
	"arch/internal/helper/constants"
	s3_aws "arch/internal/helper/s3aws"
	"arch/internal/model"
	"arch/internal/model/converter"
	"arch/internal/repository"
	"arch/pkg/apperror"
	"arch/pkg/appjwt"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	MODULE             string = "users"
	CURRENT_YEAR       int    = time.Now().Year()
	CURRENT_MONTH      int    = int(time.Now().Month())
	PREFIX_FILE_UPLOAD string = fmt.Sprintf("%s/%d/%d", MODULE, CURRENT_YEAR, CURRENT_MONTH)
	maxLoginAttempts   int    = 3
)

type AuthUseCase struct {
	AuthDatabase   model.AuthDatabase
	IthubDatabase  model.IthubDatabase
	Config         *viper.Viper
	Log            *logrus.Logger
	Redis          *redis.Client
	Jwt            *appjwt.JwtWrapper
	ProducerRMQ    *producer.RabbitMQProducer
	AwsS3          *s3.Client
	UserRepository *repository.UserRepository
}

func NewAuthUseCase(
	authDatabase model.AuthDatabase,
	ithubDatabase model.IthubDatabase,
	config *viper.Viper,
	log *logrus.Logger,
	redis *redis.Client,
	jwt *appjwt.JwtWrapper,
	producerRMQ *producer.RabbitMQProducer,
	awsS3 *s3.Client,
	userRepository *repository.UserRepository,
) *AuthUseCase {
	return &AuthUseCase{
		AuthDatabase:   authDatabase,
		IthubDatabase:  ithubDatabase,
		Config:         config,
		Log:            log,
		Redis:          redis,
		Jwt:            jwt,
		ProducerRMQ:    producerRMQ,
		AwsS3:          awsS3,
		UserRepository: userRepository,
	}
}

func (u *AuthUseCase) Register(ctx context.Context, request *model.RegisterUserRequest) (*model.UserRegisterResponse, error) {
	tx := (*u.IthubDatabase).WithContext(ctx).Begin()
	defer tx.Rollback()

	// check email if we already have
	totalEmail, err := u.UserRepository.CountUserByEmail(tx, request.Email)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	if totalEmail > 0 {
		return nil, apperror.NewAppError(http.StatusConflict, fmt.Sprintf("email %s sudah terdaftar", request.Email))
	}

	// check username if we already have
	totalUsername, err := u.UserRepository.CountUserByUsername(tx, request.Username)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	if totalUsername > 0 {
		return nil, apperror.NewAppError(http.StatusConflict, fmt.Sprintf("username %s sudah terdaftar", request.Username))
	}

	now := time.Now()
	user := &entity.User{
		Name:      request.Name,
		Username:  request.Username,
		Email:     request.Email,
		Password:  request.Password,
		Pin:       request.Pin,
		LastLogin: &now,
	}
	// save user to database
	if err := u.UserRepository.Create(tx, user); err != nil {
		u.Log.Warnf("Failed create user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	loginUser := entity.LoginUser{
		UserID:        user.ID,
		UserAgent:     request.UserAgent,
		IpAddress:     request.IpAddress,
		FirebaseToken: request.FirebaseToken,
		Model:         request.Model,
	}

	if err := u.UserRepository.CreateLoginUser(tx, &loginUser); err != nil {
		u.Log.Warnf("Failed create login user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// commit transaction
	if err := tx.Commit().Error; err != nil {
		u.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	payload := model.UserProfileResponse{
		ID:       loginUser.ID,
		UserID:   user.ID,
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email,
	}
	accessToken, err := u.Jwt.GenerateAccessToken(payload)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	refreshToken, err := u.Jwt.GenerateRefreshToken(payload)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	loginUser.RefreshToken = &refreshToken
	if err = u.UserRepository.UpdateLoginUser(tx, &loginUser); err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	return &model.UserRegisterResponse{
		User: model.UserResponse{
			ID:       user.ID,
			Name:     user.Name,
			Username: user.Username,
			Email:    user.Email,
		},
		Token: model.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil

}

func (u *AuthUseCase) Login(ctx context.Context, request *model.LoginUserRequest) (*model.UserLoginResponse, error) {
	ithub := (*u.IthubDatabase).WithContext(ctx)
	auth := (*u.AuthDatabase).WithContext(ctx).Begin()
	defer auth.Rollback()

	user := new(entity.User)
	// check user by username or email
	if err := u.UserRepository.FindUserByUsernameOrEmail(ithub, user, request.User); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.Log.Warnf("Failed find user by user or email : %+v", err)
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// check user status
	if !user.IsActive {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "your account is not active")
	}

	// if user exists, check login attempt
	key := fmt.Sprintf("login_attempt:%s", user.ID)
	var expCache float64 = 5 // 5 minutes

	loginAttemptString, err := u.Redis.Get(ctx, key).Result()
	if err != nil && err != redis.Nil {
		// Handle Redis error (other than key not found)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	loginAttempt := 0
	if err == nil {
		// Key exists, convert the retrieved string to an integer
		if attempt, convErr := strconv.Atoi(loginAttemptString); convErr != nil {
			// Handle conversion error
			return nil, apperror.NewAppError(http.StatusInternalServerError, "invalid login attempt value")
		} else {
			loginAttempt = attempt
		}
	}

	if loginAttempt > maxLoginAttempts {
		return nil, apperror.NewAppError(http.StatusUnauthorized, fmt.Sprintf("anda sudah mencoba 3 kali login dan gagal, silahkan coba lagi dalam %d menit", int(expCache)))
	}

	// check password user
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		u.Log.Warnf("Failed to compare user password with bcrype hash : %+v", err)
		// increment login attempt and save it to Redis
		loginAttempt++
		err := u.Redis.Set(ctx, key, loginAttempt, time.Duration(expCache*float64(time.Minute))).Err()
		if err != nil {
			return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
		}
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	// check login user device
	// totalLoginUser, err := u.UserRepository.CountLoginUser(tx, user.ID)
	// if err != nil {
	// 	return nil, apperror.NewAppError(http.StatusUnauthorized)
	// }
	// if totalLoginUser > maxLoginUser {
	// 	return nil, apperror.NewAppError(http.StatusUnauthorized, "maksimal login 5 perangkat, anda sudah login 5 perangkat silahkan logout disalah satu perangkat atau hubungi IT")
	// }

	now := time.Now()
	user.LastLogin = &now
	if err := u.UserRepository.UpdateUser(ithub, user); err != nil {
		u.Log.Warnf("Failed update user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	loginUser := entity.LoginUser{
		UserID:        user.ID,
		UserAgent:     request.UserAgent,
		IpAddress:     request.IpAddress,
		FirebaseToken: request.FirebaseToken,
		Model:         request.Model,
	}

	if err := u.UserRepository.CreateLoginUser(auth, &loginUser); err != nil {
		u.Log.Warnf("Failed create login user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// commit transaction
	if err := auth.Commit().Error; err != nil {
		u.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	payload := model.UserProfileResponse{
		ID:       loginUser.ID,
		UserID:   user.ID,
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email,
	}
	accessToken, err := u.Jwt.GenerateAccessToken(payload)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	refreshToken, err := u.Jwt.GenerateRefreshToken(payload)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	loginUser.RefreshToken = &refreshToken
	if err = u.UserRepository.UpdateLoginUser(u.AuthDatabase, &loginUser); err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	return &model.UserLoginResponse{
		User: model.UserResponse{
			ID:       user.ID,
			Name:     user.Name,
			Username: user.Username,
			Email:    user.Email,
		},
		Token: model.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil
}

func (u *AuthUseCase) VerifyAccessToken(ctx context.Context, tokenEncrypt string) (*model.UserProfileResponse, error) {
	ithub := (*u.IthubDatabase).WithContext(ctx)
	auth := (*u.AuthDatabase).WithContext(ctx)
	key := fmt.Sprintf("verify_access_token:%s", tokenEncrypt)
	var expCache float64 = 2
	verifyAccessToken, err := u.Redis.Get(ctx, key).Result()
	if err != nil && err != redis.Nil {
		// Handle Redis error (other than key not found)
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}
	if err == nil {
		// Declare a variable of the struct type
		userProfileCache := new(model.UserProfileResponse)

		// Unmarshal (convert) the JSON into the Go struct
		err := json.Unmarshal([]byte(verifyAccessToken), &userProfileCache)
		if err != nil {
			return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
		}

		// check blacklist token
		blacklistKey := fmt.Sprintf("blacklist_login_user:%s", userProfileCache.ID)
		loginTokenExists, err := u.Redis.Get(ctx, blacklistKey).Result()
		if err != nil && err != redis.Nil {
			// Redis error, return unauthorized
			return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
		}
		// If `loginTokenExists` is not empty, it means the token is blacklisted
		if loginTokenExists != "" {
			return nil, apperror.NewAppError(http.StatusUnauthorized, "token is blacklisted and cannot be used")
		}

		// userProfileCacheJson, err := json.Marshal(userProfileCache)
		// if err != nil {
		// 	return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
		// }
		// u.ProducerRMQ.PublishMessage(ctx, "notification", "fcm", "application/json", []byte(userProfileCacheJson))
		return userProfileCache, nil
	}

	claims, err := u.Jwt.ValidateAccessToken(tokenEncrypt)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	// check blacklist token
	blacklistKey := fmt.Sprintf("blacklist_login_user:%s", claims.ID)
	loginTokenExists, err := u.Redis.Get(ctx, blacklistKey).Result()
	if err != nil && err != redis.Nil {
		// Redis error, return unauthorized
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}
	// If `loginTokenExists` is not empty, it means the token is blacklisted
	if loginTokenExists != "" {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "token is blacklisted and cannot be used")
	}

	ok, err := u.UserRepository.FindUserByLoginUserID(auth, claims.ID)
	if !ok || err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	u.Log.Info(ok, err)

	user := new(entity.User)
	// check user by username or email
	if err := u.UserRepository.FindById(ithub, user, claims.UserID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.Log.Warnf("Failed find user by id : %+v", err)
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	response := &model.UserProfileResponse{
		ID:     claims.ID,
		UserID: user.ID,
		Name:   user.Name,
		Email:  user.Email,
	}

	// Key exists set data to redis
	jsonData, err := json.Marshal(response)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}
	err = u.Redis.Set(ctx, key, jsonData, time.Duration(expCache*float64(time.Minute))).Err()
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	return response, nil
}

func (u *AuthUseCase) VerifyRefreshToken(ctx context.Context, tokenEncrypt string) (string, error) {
	ithub := (*u.IthubDatabase).WithContext(ctx)
	auth := (*u.AuthDatabase).WithContext(ctx)
	claims, err := u.Jwt.ValidateRefreshToken(tokenEncrypt)
	if err != nil {
		return "", apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	ok, err := u.UserRepository.FindUserByLoginUserID(auth, claims.ID)
	if !ok || err != nil {
		return "", apperror.NewAppError(http.StatusUnauthorized)
	}

	user := new(entity.User)
	// check user by username or email
	if err := u.UserRepository.FindById(ithub, user, claims.UserID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.Log.Warnf("Failed find user by od : %+v", err)
			return "", apperror.NewAppError(http.StatusUnauthorized)
		}
		return "", apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	payload := model.UserProfileResponse{
		ID:       claims.ID,
		UserID:   user.ID,
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email,
	}
	newToken, err := u.Jwt.GenerateAccessToken(payload)
	if err != nil {
		return "", apperror.NewAppError(http.StatusUnauthorized)
	}

	return newToken, nil
}

func (u *AuthUseCase) UpdatePassword(ctx context.Context, request *model.UpdatePasswordLoginRequest) error {
	tx := (*u.IthubDatabase).WithContext(ctx).Begin()
	defer tx.Rollback()

	user := new(entity.User)
	if err := u.UserRepository.FindById(tx, user, request.ID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.Log.Warnf("Failed find user by user or email : %+v", err)
			return apperror.NewAppError(http.StatusBadRequest)
		}
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// check password user
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.OldPassword)); err != nil {
		u.Log.Warnf("Failed to compare user password with bcrype hash : %+v", err)
		return apperror.NewAppError(http.StatusBadRequest, "password lama yang anda masukkan salah")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		u.Log.Warnf("Failed update suer : %+v", err)
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	user.Password = string(passwordHash)
	if err := u.UserRepository.UpdateUser(tx, user); err != nil {
		u.Log.Warnf("Failed update user : %+v", err)
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Warnf("Failed commit transaction : %+v", err)
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	return nil
}

func (u *AuthUseCase) Logout(ctx context.Context, request *model.UserProfileResponse) error {
	tx := (*u.IthubDatabase).WithContext(ctx).Begin()
	defer tx.Rollback()

	// find login user in database
	loginUser := new(entity.LoginUser)
	if err := u.UserRepository.FindByIdLoginUser(tx, loginUser, request.ID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return apperror.NewAppError(http.StatusUnauthorized)
		}
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// delete row if exists
	if err := u.UserRepository.DeleteLoginUser(tx, loginUser, request.ID); err != nil {
		u.Log.Warnf("Failed delete : %+v", err)
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// delete cache in redis
	key := fmt.Sprintf("verify_access_token:%s", request.ID)
	_, err := u.Redis.Del(ctx, key).Result()
	if err != nil {
		// Handle Redis error (other than key not found)
		return apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	// set data blacklist token in redis
	var expCache float64 = 1 // 1 hours
	blacklistKey := fmt.Sprintf("blacklist_login_user:%s", request.ID)
	err = u.Redis.Set(ctx, blacklistKey, request.ID, time.Duration(expCache*float64(time.Hour))).Err()
	if err != nil {
		return apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Warnf("Failed commit transaction : %+v", err)
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	return nil
}

func (u *AuthUseCase) FindLoginUserByUserId(ctx context.Context, request string) ([]model.LoginUserResponse, error) {
	tx := (*u.IthubDatabase).WithContext(ctx)
	loginUser, err := u.UserRepository.FindLoginUserByUserId(tx, request)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	responses := make([]model.LoginUserResponse, len(loginUser))
	for i, user := range loginUser {
		responses[i] = *converter.LoginUserToResponse(&user)
	}
	return responses, nil
}

func (u *AuthUseCase) ForceLogout(ctx context.Context, request *model.ForceLogoutRequest) error {
	tx := (*u.IthubDatabase).WithContext(ctx).Begin()
	defer tx.Rollback()

	if err := u.UserRepository.DeleteMultipleLoginUser(tx, request.IDs); err != nil {
		u.Log.Warnf("Failed delete multiple login user : %+v", err)
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	if err := tx.Commit().Error; err != nil {
		u.Log.Warnf("Failed commit transaction : %+v", err)
		return apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	return nil
}

func (u *AuthUseCase) UploadPhotoProfile(ctx context.Context, request *model.UploadPhotoProfile) error {
	if err := u.putFiles(ctx, request.Files, request.ID); err != nil {
		return apperror.NewAppError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func (u *AuthUseCase) GetPhotoProfile(ctx context.Context) (*v4.PresignedHTTPRequest, error) {
	objectKey := "users/2024/11/1/1730872668971544852_RoYH0lQ0.png"
	presigned, err := s3_aws.GetObjectFromS3(ctx, u.AwsS3, u.Config.GetString("aws.s3.bucket"), objectKey)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusBadRequest, err.Error())
	}
	return presigned, nil
}

func (u *AuthUseCase) putFiles(ctx context.Context, files []*multipart.FileHeader, userId string) error {
	if len(files) > 10 {
		return errors.New("too many files, max 10 files")
	}
	var errorMessage string

	var messages []model.AwsS3UploadMessage
	// Process and upload files if needed
	for _, file := range files {
		// Validate file size (e.g., max 100 MB)
		if err := helper.ValidateFileExtension(file, constants.ALLOWED_FILE_UPLOAD_APPROVAL_ATTACHMENT, constants.MAX_SIZE_FILE_APPROVAL_ATTACHMENT); err != nil {
			errorMessage = err.Error()
			break
		}

		buf, err := helper.ReadFileToBuffer(file)
		if err != nil {
			errorMessage = err.Error()
			break
		}

		// Create the message
		filename := helper.GenerateCustomFilename(file.Filename)
		directory := fmt.Sprintf("%s/%s/%s", PREFIX_FILE_UPLOAD, userId, filename)

		// create message fro rabbitmq
		message := model.AwsS3UploadMessage{
			Directory:  directory,
			FileBuffer: buf.Bytes(),
		}
		messages = append(messages, message)
	}
	if errorMessage != "" {
		return errors.New(errorMessage)
	}

	if len(messages) > 0 {
		for _, message := range messages {
			// convert message to byte
			messageBody, err := json.Marshal(message)
			if err != nil {
				errorMessage = err.Error()
				break
			}
			// send to rabbitmq for upload file to aws s3
			u.ProducerRMQ.PublishMessage(ctx, "aws", "s3_put_object", "application/json", messageBody)
		}
	}
	if errorMessage != "" {
		return errors.New(errorMessage)
	}
	return nil
}

func (u *AuthUseCase) GetUserByPersonalEmail(ctx context.Context, request *model.LoginUserByPersonalEmailRequest) (*model.UserLoginResponse, error) {
	tx := (*u.IthubDatabase).WithContext(ctx).Begin()
	defer tx.Rollback()

	user := new(model.LoginUserByPersonalEmail)
	// check user by personal email
	if err := u.UserRepository.FindUserByPersonalEmail(tx, user, request.PersonalEmail); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// if user exists, check login attempt
	key := fmt.Sprintf("login_attempt:%s", user.ID)
	var expCache float64 = 5 // 5 minutes

	loginAttemptString, err := u.Redis.Get(ctx, key).Result()
	if err != nil && err != redis.Nil {
		// Handle Redis error (other than key not found)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	loginAttempt := 0
	if err == nil {
		// Key exists, convert the retrieved string to an integer
		if attempt, convErr := strconv.Atoi(loginAttemptString); convErr != nil {
			// Handle conversion error
			return nil, apperror.NewAppError(http.StatusInternalServerError, "invalid login attempt value")
		} else {
			loginAttempt = attempt
		}
	}

	if loginAttempt > maxLoginAttempts {
		return nil, apperror.NewAppError(http.StatusUnauthorized, fmt.Sprintf("anda sudah mencoba 3 kali login dan gagal, silahkan coba lagi dalam %d menit", int(expCache)))
	}

	// now := time.Now()
	// user.LastLogin = &now
	// if err := u.UserRepository.UpdateUser(tx, user); err != nil {
	// 	u.Log.Warnf("Failed update user to database : %+v", err)
	// 	return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	// }

	loginUser := entity.LoginUser{
		UserID:        user.ID,
		UserAgent:     request.UserAgent,
		IpAddress:     request.IpAddress,
		FirebaseToken: request.FirebaseToken,
		Model:         request.Model,
	}

	if err := u.UserRepository.CreateLoginUser(tx, &loginUser); err != nil {
		u.Log.Warnf("Failed create login user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// commit transaction
	if err := tx.Commit().Error; err != nil {
		u.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	payload := model.UserProfileResponse{
		ID:       loginUser.ID,
		UserID:   user.ID,
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email,
	}
	accessToken, err := u.Jwt.GenerateAccessToken(payload)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	refreshToken, err := u.Jwt.GenerateRefreshToken(payload)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	loginUser.RefreshToken = &refreshToken
	if err = u.UserRepository.UpdateLoginUser(tx, &loginUser); err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	return &model.UserLoginResponse{
		User: model.UserResponse{
			ID:       user.ID,
			Name:     user.Name,
			Username: user.Username,
			Email:    user.Email,
		},
		Token: model.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil
}

func (u *AuthUseCase) GetAllFirebaseTokenByUserIds(ctx context.Context, userIds []string) ([]model.DataFirebaseToken, error) {
	if len(userIds) < 1 {
		return nil, errors.New("user ids must not be empty")
	}
	tx := (*u.IthubDatabase).WithContext(ctx)
	result, err := u.UserRepository.GetAllFirebaseTokenByUserIds(tx, userIds)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (u *AuthUseCase) GenerateOtp(ctx context.Context, request *model.UserProfileResponse) (string, error) {
	tx := (*u.IthubDatabase).WithContext(ctx).Begin()
	defer tx.Rollback()

	u.Log.Infof("request : %v", request)
	user := new(entity.User)
	if err := u.UserRepository.FindById(tx, user, request.UserID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", apperror.NewAppError(http.StatusUnauthorized)
		}
		return "", apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	issuer := u.Config.GetString("app.name")
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.Email,
	})
	if err != nil {
		return "", err
	}
	secretCode := secret.Secret()

	user.OTPSecret = &secretCode
	if err := u.UserRepository.UpdateUser(tx, user); err != nil {
		return "", apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	if err := tx.Commit().Error; err != nil {
		return "", apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// otpauth://totp/YourAppName:user@example.com?secret=ABCD1234&issuer=YourAppName
	otpURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, user.Email, secretCode, issuer)
	return otpURL, nil

}

func (u *AuthUseCase) ValidateOTP(ctx context.Context, request *model.ValidateOTPRequest) (bool, error) {
	tx := (*u.IthubDatabase).WithContext(ctx)
	defer tx.Rollback()

	user := new(entity.User)
	// check user by username or email
	if err := u.UserRepository.FindOtpSecretUserByID(tx, user, request.UserID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.Log.Warnf("Failed find user by user or email : %+v", err)
			return false, apperror.NewAppError(http.StatusUnauthorized)
		}
		return false, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}
	ok := totp.Validate(request.OTP, *user.OTPSecret)

	return ok, nil
}
