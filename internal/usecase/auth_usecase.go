package usecase

import (
	"arch/internal/entity"
	"arch/internal/model"
	"arch/internal/repository"
	"arch/pkg/apperror"
	"arch/pkg/appjwt"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthUseCase struct {
	Database       *gorm.DB
	UserRepository *repository.UserRepository
	Config         *viper.Viper
	Logger         *logrus.Logger
	Redis          *redis.Client
	Jwt            *appjwt.JwtWrapper
}

func NewAuthUseCase(database *gorm.DB,
	userRepository *repository.UserRepository,
	config *viper.Viper,
	logger *logrus.Logger,
	redis *redis.Client,
	jwt *appjwt.JwtWrapper,
) *AuthUseCase {
	return &AuthUseCase{
		Database:       database,
		UserRepository: userRepository,
		Config:         config,
		Logger:         logger,
		Redis:          redis,
		Jwt:            jwt,
	}
}

func (u *AuthUseCase) Register(ctx context.Context, request *model.RegisterUserRequest) (*model.UserRegisterResponse, error) {
	tx := u.Database.WithContext(ctx).Begin()
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

	user := &entity.User{
		Name:     request.Name,
		Username: request.Username,
		Email:    request.Email,
		Password: request.Password,
	}
	// save user to database
	if err := u.UserRepository.Create(tx, user); err != nil {
		u.Logger.Warnf("Failed create user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	loginUser := entity.LoginUser{
		UserID:    user.ID,
		UserAgent: request.UserAgent,
		IpAddress: request.IpAddress,
	}

	if err := u.UserRepository.CreateLoginUser(tx, &loginUser); err != nil {
		u.Logger.Warnf("Failed create login user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// commit transaction
	if err := tx.Commit().Error; err != nil {
		u.Logger.Warnf("Failed commit transaction : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	accessToken, err := u.Jwt.GenerateAccessToken(loginUser.ID)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	refreshToken, err := u.Jwt.GenerateRefreshToken(user.CredentialID)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
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
	tx := u.Database.WithContext(ctx).Begin()
	defer tx.Rollback()

	user := new(entity.User)
	// check user by username or email
	if err := u.UserRepository.FindUserByUsernameOrEmail(tx, user, request.User); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.Logger.Warnf("Failed find user by user or email : %+v", err)
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// if user exists, check login attempt
	key := fmt.Sprintf("login_attempt:%s", user.ID)
	var expCache float64 = 5

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

	if loginAttempt > 3 {
		return nil, apperror.NewAppError(http.StatusUnauthorized, fmt.Sprintf("anda sudah mencoba 3 kali login dan gagal, silahkan coba lagi dalam %d menit", int(expCache)))
	}

	// check password user
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		u.Logger.Warnf("Failed to compare user password with bcrype hash : %+v", err)
		// increment login attempt and save it to Redis
		loginAttempt++
		err := u.Redis.Set(ctx, key, loginAttempt, time.Duration(expCache*float64(time.Minute))).Err()
		if err != nil {
			return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
		}
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	loginUser := entity.LoginUser{
		UserID:    user.ID,
		UserAgent: request.UserAgent,
		IpAddress: request.IpAddress,
	}

	if err := u.UserRepository.CreateLoginUser(tx, &loginUser); err != nil {
		u.Logger.Warnf("Failed create login user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// commit transaction
	if err := tx.Commit().Error; err != nil {
		u.Logger.Warnf("Failed commit transaction : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	accessToken, err := u.Jwt.GenerateAccessToken(loginUser.ID)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	refreshToken, err := u.Jwt.GenerateRefreshToken(user.CredentialID)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	return &model.UserLoginResponse{
		User: model.UserResponse{
			ID:       user.CredentialID,
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
	key := fmt.Sprintf("verify_access_token:%s", tokenEncrypt)
	var expCache float64 = 5
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
		return userProfileCache, nil
	}
	claims, err := u.Jwt.ValidateAccessToken(tokenEncrypt)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	loginUser := new(model.LoginUserQueryResponse)
	if err := u.UserRepository.FindUserByLoginUserID(u.Database, loginUser, claims.ID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	response := &model.UserProfileResponse{
		ID:     loginUser.ID,
		UserID: loginUser.UserID,
		Name:   loginUser.Name,
		Email:  loginUser.Email,
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

func (u *AuthUseCase) VerifyRefreshToken(ctx context.Context, tokenEncrypt string) (*model.UserProfileResponse, error) {
	key := fmt.Sprintf("verify_refresh_token:%s", tokenEncrypt)
	var expCache float64 = 5
	verifyToken, err := u.Redis.Get(ctx, key).Result()
	if err != nil && err != redis.Nil {
		// Handle Redis error (other than key not found)
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}
	if err == nil {
		// Declare a variable of the struct type
		userProfileCache := new(model.UserProfileResponse)

		// Unmarshal (convert) the JSON into the Go struct
		err := json.Unmarshal([]byte(verifyToken), &userProfileCache)
		if err != nil {
			return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
		}
		return userProfileCache, nil
	}
	claims, err := u.Jwt.ValidateRefreshToken(tokenEncrypt)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	loginUser := new(model.LoginUserQueryResponse)
	if err := u.UserRepository.FindUserByLoginUserID(u.Database, loginUser, claims.ID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	response := &model.UserProfileResponse{
		ID:     loginUser.ID,
		UserID: loginUser.UserID,
		Name:   loginUser.Name,
		Email:  loginUser.Email,
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
