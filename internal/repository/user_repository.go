package repository

import (
	"arch/internal/entity"
	"arch/internal/model"
	"arch/pkg/apperror"
	"net/http"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserRepository struct {
	Repository[entity.User]
	Logger *logrus.Logger
}

func NewUserRepository(logger *logrus.Logger) *UserRepository {
	return &UserRepository{
		Logger: logger,
	}
}

func (r *UserRepository) CountUserByUsername(database *gorm.DB, username string) (int64, error) {
	var count int64
	if err := database.Table("users").
		Where("username = ?", username).
		Where("deleted_at IS NULL").
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *UserRepository) CountUserByEmail(database *gorm.DB, email string) (int64, error) {
	var count int64
	if err := database.Table("users").
		Where("email = ?", email).
		Where("deleted_at IS NULL").
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *UserRepository) FindUserByUsernameOrEmail(database *gorm.DB, user *entity.User, id string) error {
	return database.
		Where("username = ? OR email = ?", id, id).
		Where("deleted_at IS NULL").
		Take(&user).
		Error
}

func (r *UserRepository) FindOtpSecretUserByID(database *gorm.DB, user *entity.User, id string) error {
	return database.
		Select("otp_secret").
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Take(&user).
		Error
}

func (r *UserRepository) FindOtpSecretUserByUsername(database *gorm.DB, user *entity.User, username string) error {
	return database.
		Where("username = ?", username).
		Where("deleted_at IS NULL").
		Take(&user).
		Error
}

func (r *UserRepository) FindUserByLoginUserID(database *gorm.DB, loginUserId string) (bool, error) {
	var total int64
	if err := database.Table("login_user").
		Where("id = ?", loginUserId).
		Count(&total).Error; err != nil {
		return false, err
	}

	if total == 0 {
		return false, apperror.NewAppError(http.StatusNotFound, "login user not found")
	}

	return true, nil
}

func (r *UserRepository) CreateLoginUser(database *gorm.DB, entity *entity.LoginUser) error {
	return database.Create(entity).Error
}

func (r *UserRepository) UpdateUser(database *gorm.DB, user *entity.User) error {
	query := "UPDATE users SET name = ?, username = ?, email = ?, is_active = ?, password = ?, verified_at = ?, last_login = ?, pin = ?, otp_secret = ? WHERE id = ? AND deleted_at IS NULL"
	return database.Exec(query, user.Name, user.Username, user.Email, user.IsActive, user.Password, user.VerifiedAt, user.LastLogin, user.Pin, user.OTPSecret, user.ID).Error
}

func (r *UserRepository) FindByIdLoginUser(database *gorm.DB, entity *entity.LoginUser, id string) error {
	return database.Where("id = ?", id).Take(&entity).Error
}

func (r *UserRepository) FindByKeyLoginUser(database *gorm.DB, entity *entity.LoginUser, key string) error {
	return database.Where("key = ?", key).Take(&entity).Error
}

func (r *UserRepository) FindLoginUserByUserId(database *gorm.DB, userID string) ([]entity.LoginUser, error) {
	var loginUser []entity.LoginUser
	if err := database.Where("user_id = ?", userID).Find(&loginUser).Error; err != nil {
		return nil, err
	}
	return loginUser, nil
}

func (r *UserRepository) CountLoginUser(database *gorm.DB, userID string) (int64, error) {
	var total int64
	if err := database.Table("login_user").
		Where("user_id = ?", userID).
		Count(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

func (r *UserRepository) UpdateLoginUser(db *gorm.DB, loginUser *entity.LoginUser) error {
	query := "UPDATE login_user SET firebase_token = ?, model = ?, refresh_token = ?, is_validated = ? WHERE id = ?"
	return db.Exec(query, loginUser.FirebaseToken, loginUser.Model, loginUser.RefreshToken, loginUser.IsValidated, loginUser.ID).Error
}

func (r *UserRepository) DeleteLoginUser(database *gorm.DB, entity *entity.LoginUser, id string) error {
	return database.Where("id = ?", id).Delete(entity).Error
}

func (r *UserRepository) DeleteMultipleLoginUser(database *gorm.DB, ids []string) error {
	query := "DELETE FROM login_user WHERE id IN (?)"
	return database.Exec(query, ids).Error
}

func (r *UserRepository) FindUserByPersonalEmail(database *gorm.DB, user *model.LoginUserByPersonalEmail, personalEmail string) error {
	return database.Table("users AS a").
		Select("b.personal_email, a.name, a.email, a.username, a.id").
		Where("a.is_active = ?", true).
		Where("b.personal_email = ?", personalEmail).
		Where("a.deleted_at IS NULL").
		Joins("JOIN u_employees AS b ON a.id = b.user_id").
		Scan(&user).
		Error
}

func (r *UserRepository) FindUserByID(database *gorm.DB, user *model.UserResponse, id string) error {
	return database.Table("users AS a").
		Select("a.id, a.name, a.username, a.email, b.personal_email, b.nip").
		Where("a.deleted_at IS NULL").
		Where("a.is_active = ?", true).
		Where("a.id = ?", id).
		Joins("JOIN u_employees AS b ON a.id = b.user_id").
		Scan(&user).
		Error
}

func (r *UserRepository) GetAllFirebaseTokenByUserIds(database *gorm.DB, userIds []string) ([]model.DataFirebaseToken, error) {
	var results []model.DataFirebaseToken
	err := database.Table("login_user AS a").
		Select("a.firebase_token, b.name").
		Where("a.firebase_token IS NOT NULL").
		Where("b.deleted_at IS NULL").
		Where("a.user_id IN (?)", userIds).
		Joins("JOIN users AS b ON b.id = a.user_id").
		Scan(&results).
		Error
	if err != nil {
		return nil, err
	}

	return results, nil
}
