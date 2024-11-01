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

func (r *UserRepository) FindUserByLoginUserID(database *gorm.DB, loginUser *model.LoginUserQueryResponse, loginUserId string) error {
	var total int64
	if err := database.Table("login_user").
		Where("id = ?", loginUserId).
		Count(&total).Error; err != nil {
		return err
	}

	if total == 0 {
		return apperror.NewAppError(http.StatusNotFound, "login user not found")
	}

	query := `SELECT
				a.id, b.name, b.username, b.email, a.user_id, a.created_at
				FROM
					login_user a
				JOIN 
					users b ON a.user_id = b.id
				AND 
					a.id = ?
				LIMIT 1`
	return database.Raw(query, loginUserId).Scan(&loginUser).Error
}
func (r *UserRepository) CreateLoginUser(database *gorm.DB, entity *entity.LoginUser) error {
	return database.Create(entity).Error
}

func (r *UserRepository) UpdateUser(database *gorm.DB, user *entity.User) error {
	query := "UPDATE users SET name = ?, username = ?, email = ?, is_active = ?, password = ?, verified_at = ?, last_login = ?, pin = ? WHERE id = ? AND deleted_at IS NULL"
	return database.Exec(query, user.Name, user.Username, user.Email, user.IsActive, user.Password, user.VerifiedAt, user.LastLogin, user.Pin, user.ID).Error
}

func (r *UserRepository) FindByIdLoginUser(database *gorm.DB, entity *entity.LoginUser, id string) error {
	return database.Where("id = ?", id).Take(&entity).Error
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
	query := "UPDATE login_user SET firebase_token = ?, model = ?, refresh_token = ? WHERE id = ?"
	return db.Exec(query, loginUser.FirebaseToken, loginUser.Model, loginUser.RefreshToken, loginUser.ID).Error
}

func (r *UserRepository) DeleteLoginUser(database *gorm.DB, entity *entity.LoginUser, id string) error {
	return database.Where("id = ?", id).Delete(entity).Error
}

func (r *UserRepository) DeleteMultipleLoginUser(database *gorm.DB, ids []string) error {
	query := "DELETE FROM login_user WHERE id IN (?)"
	return database.Exec(query, ids).Error
}
