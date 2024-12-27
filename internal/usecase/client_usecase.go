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
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"

	"golang.org/x/oauth2"
)

type ClientUseCase struct {
	AuthDatabase     model.AuthDatabase
	IthubDatabase    model.IthubDatabase
	Config           *viper.Viper
	Log              *logrus.Logger
	Redis            *redis.Client
	Jwt              *appjwt.JwtWrapper
	ClientRepository *repository.ClientRepository
	UserRepository   *repository.UserRepository
}

func NewClientUseCase(
	authDatabase model.AuthDatabase,
	ithubDatabase model.IthubDatabase,
	config *viper.Viper,
	log *logrus.Logger,
	redis *redis.Client,
	jwt *appjwt.JwtWrapper,
	clientRepository *repository.ClientRepository,
	userRepository *repository.UserRepository,
) *ClientUseCase {
	return &ClientUseCase{
		AuthDatabase:     authDatabase,
		IthubDatabase:    ithubDatabase,
		Config:           config,
		Log:              log,
		Redis:            redis,
		Jwt:              jwt,
		ClientRepository: clientRepository,
		UserRepository:   userRepository,
	}
}

func (u *ClientUseCase) GetAll(ctx context.Context) ([]entity.Client, error) {
	tx := (*u.AuthDatabase).WithContext(ctx)
	clients, err := u.ClientRepository.GetAll(tx)
	if err != nil {
		u.Log.Error(err)
		return nil, err
	}
	return clients, nil
}

func (u *ClientUseCase) Create(ctx context.Context, request *model.ClientRequest) (*entity.Client, error) {
	tx := (*u.AuthDatabase).WithContext(ctx).Begin()
	defer tx.Rollback()

	re := regexp.MustCompile(`\s+`) // Match one or more spaces
	name := strings.ToLower(re.ReplaceAllString(request.Name, "_"))
	// check email if we already have
	totalName, err := u.ClientRepository.CountClientByColumn(tx, "name", name)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	if totalName > 0 {
		return nil, apperror.NewAppError(http.StatusConflict, fmt.Sprintf("name %s sudah ada", request.Name))
	}

	// check email if we already have
	totalBaseURL, err := u.ClientRepository.CountClientByColumn(tx, "base_url", request.BaseURL)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	if totalBaseURL > 0 {
		return nil, apperror.NewAppError(http.StatusConflict, fmt.Sprintf("base URL %s sudah ada", request.BaseURL))
	}

	result := &entity.Client{
		Name:        name,
		BaseURL:     request.BaseURL,
		CallbackURL: request.CallbackURL,
		Enabled:     request.Enabled,
		Description: request.Description,
	}
	// save user to database
	if err := u.ClientRepository.Create(tx, result); err != nil {
		u.Log.Warnf("Failed create clients to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// commit transaction
	if err := tx.Commit().Error; err != nil {
		u.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	return result, nil
}

func (u *ClientUseCase) ClientLogin(ctx context.Context, request *model.ClientLoginUserRequest) (*model.ClientUserLoginResponse, error) {
	auth := (*u.AuthDatabase).WithContext(ctx).Begin()
	ithub := (*u.IthubDatabase).WithContext(ctx)
	defer auth.Rollback()

	client := new(entity.Client)
	if err := u.ClientRepository.FindByName(auth, client, request.ClientName); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.Log.Warnf("Failed find client name : %+v", err)
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	if !client.Enabled {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "your app is not active")
	}

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
	key := fmt.Sprintf("client_login_attempt:%s", user.ID)
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

	now := time.Now()
	user.LastLogin = &now
	if err := u.UserRepository.UpdateUser(ithub, user); err != nil {
		u.Log.Warnf("Failed update user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// Get the current time
	unixNanoTimestamp := time.Now().UnixNano()
	// Get Unix timestamp with nanoseconds precision
	nanoid, err := gonanoid.New()
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	keyLogin := fmt.Sprintf("%d:%s", unixNanoTimestamp, nanoid)
	loginUser := entity.LoginUser{
		UserID:        user.ID,
		UserAgent:     request.UserAgent,
		Key:           keyLogin,
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

	return &model.ClientUserLoginResponse{
		Token:       keyLogin,
		CallbackURL: fmt.Sprintf("%s?token=%s", client.CallbackURL, keyLogin),
	}, nil
}

func (u *ClientUseCase) VerifyKey(ctx context.Context, key string) (*model.UserLoginResponse, error) {
	auth := (*u.AuthDatabase).WithContext(ctx).Begin()
	ithub := (*u.IthubDatabase).WithContext(ctx)
	defer auth.Rollback()

	loginUser := new(entity.LoginUser)
	// check user by username or email
	if err := u.UserRepository.FindByKeyLoginUser(auth, loginUser, key); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	if loginUser.IsValidated {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "key has already been validated")
	}

	user := new(entity.User)
	// check user by username or email
	if err := u.UserRepository.FindById(ithub, user, loginUser.UserID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// check user status
	if !user.IsActive {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "your account is not active")
	}

	now := time.Now()
	user.LastLogin = &now
	if err := u.UserRepository.UpdateUser(ithub, user); err != nil {
		u.Log.Warnf("Failed update user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	employee := new(model.UserResponse)
	// check user by personal email
	if err := u.UserRepository.FindUserByID(ithub, employee, user.ID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	payload := model.UserProfileResponse{
		ID:            loginUser.ID,
		UserID:        employee.ID,
		Name:          employee.Name,
		Username:      employee.Username,
		Email:         employee.Email,
		PersonalEmail: employee.PersonalEmail,
		NIP:           employee.NIP,
	}
	accessToken, err := u.Jwt.GenerateAccessToken(payload)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError)
	}

	refreshToken, err := u.Jwt.GenerateRefreshToken(payload)
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError)
	}

	loginUser.RefreshToken = &refreshToken
	loginUser.IsValidated = true
	if err = u.UserRepository.UpdateLoginUser(auth, loginUser); err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// commit transaction
	if err := auth.Commit().Error; err != nil {
		u.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	return &model.UserLoginResponse{
		User: model.UserResponse{
			ID:            employee.ID,
			Name:          employee.Name,
			Username:      employee.Username,
			Email:         employee.Email,
			PersonalEmail: employee.PersonalEmail,
			NIP:           employee.NIP,
		},
		Token: model.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil
}

func (u *ClientUseCase) ClientLoginWithOtp(ctx context.Context, request *model.ClientLoginUserOTPRequest) (*model.ClientUserLoginResponse, error) {
	ithub := (*u.IthubDatabase).WithContext(ctx)
	auth := (*u.AuthDatabase).WithContext(ctx).Begin()
	defer auth.Rollback()

	user := new(entity.User)
	if err := u.UserRepository.FindUserByUsernameOrEmail(ithub, user, request.Username); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusUnauthorized, err.Error())
	}

	// check user status
	if !user.IsActive {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "your account is not active")
	}

	ok := totp.Validate(request.OTP, *user.OTPSecret)
	if !ok {
		return nil, apperror.NewAppError(http.StatusUnauthorized)
	}

	client := new(entity.Client)
	if err := u.ClientRepository.FindByName(auth, client, request.ClientName); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.Log.Warnf("Failed find client: %+v", err)
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	if !client.Enabled {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "your app is not active")
	}

	// if user exists, check login attempt
	key := fmt.Sprintf("client_login_attempt:%s", user.ID)
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

	now := time.Now()
	user.LastLogin = &now
	if err := u.UserRepository.UpdateUser(ithub, user); err != nil {
		u.Log.Warnf("Failed update user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// Get the current time
	currentTime := time.Now()
	unixNanoTimestamp := currentTime.UnixNano()
	// Get Unix timestamp with nanoseconds precision
	nanoid, err := gonanoid.New()
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	keyLogin := fmt.Sprintf("%d:%s", unixNanoTimestamp, nanoid)
	loginUser := entity.LoginUser{
		UserID:        user.ID,
		UserAgent:     request.UserAgent,
		Key:           keyLogin,
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

	return &model.ClientUserLoginResponse{
		Token:       keyLogin,
		CallbackURL: fmt.Sprintf("%s?token=%s", client.CallbackURL, keyLogin),
	}, nil
}

// googleLoginHandler redirects the user to Google's OAuth2 consent page
func (u *ClientUseCase) GoogleOAuthLogin(ctx context.Context, clientName string) (string, error) {
	host := u.Config.GetString("app.host")
	port := u.Config.GetInt("app.port")
	redirectURL := fmt.Sprintf("%s:%d/%s", host, port, "api/v1/clients/google/oauth/callback")
	var oauthConfig *oauth2.Config = &oauth2.Config{
		ClientID:     u.Config.GetString("google.oauth.client_id"),
		ClientSecret: u.Config.GetString("google.oauth.client_secret"),
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// Generate a URL to Google's OAuth2 login page
	url := oauthConfig.AuthCodeURL(clientName, oauth2.AccessTypeOffline)
	return url, nil
}

func (u *ClientUseCase) GoogleOAuthCallback(ctx context.Context, state, code string) (*model.ClientUserLoginResponse, error) {
	auth := (*u.AuthDatabase).WithContext(ctx).Begin()
	ithub := (*u.IthubDatabase).WithContext(ctx)
	defer auth.Rollback()
	clientApp := new(entity.Client)
	if err := u.ClientRepository.FindByName(auth, clientApp, state); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	if !clientApp.Enabled {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "your app is not active")
	}

	host := u.Config.GetString("app.host")
	port := u.Config.GetInt("app.port")
	redirectURL := fmt.Sprintf("%s:%d/%s", host, port, "api/v1/clients/google/oauth/callback")
	var oauthConfig *oauth2.Config = &oauth2.Config{
		ClientID:     u.Config.GetString("google.oauth.client_id"),
		ClientSecret: u.Config.GetString("google.oauth.client_secret"),
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
	// Verify the state token
	if state != "kpi" {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "Invalid state token")
	}

	// Exchange the authorization code for an access token
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		return nil, apperror.NewAppError(http.StatusUnauthorized, "Failed to exchange token")
	}

	// Use the token to retrieve the user's information
	client := oauthConfig.Client(context.Background(), token)
	response, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, "Failed to get user info")
	}
	defer response.Body.Close()

	// Parse the user info
	// Use json.NewDecoder to decode the response body
	var userInfo = new(model.ClientGoogleOauthUserInfo)
	bodyBytes, err := io.ReadAll(response.Body) // Read the response body
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, "Failed to read response body")
	}

	if err := json.Unmarshal(bodyBytes, &userInfo); err != nil {
		log.Printf("Failed to parse user info: %v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, "Failed to parse user info")
	}
	if !userInfo.VerifiedEmail {
		return nil, apperror.NewAppError(http.StatusUnauthorized, "your account is not verified")
	}

	employee := new(model.LoginUserByPersonalEmail)
	// check user by personal email
	if err := u.UserRepository.FindUserByPersonalEmail(ithub, employee, userInfo.Email); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// if user exists, check login attempt
	key := fmt.Sprintf("client_login_attempt:%s", employee.ID)
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

	user := new(entity.User)
	// check user by username or email
	if err := u.UserRepository.FindById(ithub, user, employee.ID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NewAppError(http.StatusUnauthorized)
		}
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	now := time.Now()
	user.LastLogin = &now
	if err := u.UserRepository.UpdateUser(ithub, user); err != nil {
		u.Log.Warnf("Failed update user to database : %+v", err)
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}

	// Get the current time
	unixNanoTimestamp := time.Now().UnixNano()
	// Get Unix timestamp with nanoseconds precision
	nanoid, err := gonanoid.New()
	if err != nil {
		return nil, apperror.NewAppError(http.StatusInternalServerError, err.Error())
	}
	keyLogin := fmt.Sprintf("%d:%s", unixNanoTimestamp, nanoid)
	loginUser := entity.LoginUser{
		UserID: user.ID,
		Key:    keyLogin,
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

	return &model.ClientUserLoginResponse{
		Token:       keyLogin,
		CallbackURL: fmt.Sprintf("%s?token=%s", clientApp.CallbackURL, keyLogin),
	}, nil
}
