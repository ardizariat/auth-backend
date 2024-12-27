package entity

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// type User struct {
// 	ID                      string         `json:"id" gorm:"column:id;primaryKey;<-:create"`
// 	CredentialID            string         `json:"credential_id" gorm:"column:credential_id"`
// 	Name                    string         `json:"name" gorm:"column:name"`
// 	Username                string         `json:"username" gorm:"column:username"`
// 	Email                   string         `json:"email" gorm:"column:email"`
// 	PersonalEmail           *string        `json:"personal_email" gorm:"column:personal_email"`
// 	OTPSecret               *string        `json:"otp_secret" gorm:"column:otp_secret"`
// 	IsActive                bool           `json:"is_active" gorm:"column:is_active;default:true"`
// 	Password                string         `json:"-" gorm:"column:password"`
// 	VerifiedAtEmail         *time.Time     `json:"verified_at_email" gorm:"column:verified_at_email"`
// 	VerifiedAtPersonalEmail *time.Time     `json:"verified_at_personal_email" gorm:"column:verified_at_personal_email"`
// 	LastLogin               *time.Time     `json:"last_login" gorm:"column:last_login"`
// 	Pin                     *uint16        `json:"pin" gorm:"column:pin"`
// 	CreatedAt               time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime;<-:create"`
// 	UpdatedAt               time.Time      `json:"updated_at" gorm:"column:updated_at;autoCreateTime;autoUpdateTime"`
// 	DeletedAt               gorm.DeletedAt `json:"deleted_at" gorm:"index;column:deleted_at"`
// }

type User struct {
	ID           string         `json:"id" gorm:"column:id;primaryKey;<-:create"`
	Name         string         `json:"name" gorm:"column:name"`
	Username     string         `json:"username" gorm:"column:username"`
	Email        string         `json:"email" gorm:"column:email"`
	IsActive     bool           `json:"is_active" gorm:"column:is_active;default:true"`
	Password     string         `json:"-" gorm:"column:password"`
	VerifiedAt   *time.Time     `json:"verified_at" gorm:"column:verified_at"`
	RefreshToken *string        `json:"refresh_token" gorm:"column:refresh_token"`
	LoginAttempt *int           `json:"login_attempt" gorm:"column:login_attempt"`
	LastLogin    *time.Time     `json:"last_login" gorm:"column:last_login"`
	Pin          *uint16        `json:"pin" gorm:"column:pin"`
	OTPSecret    *string        `json:"otp_secret" gorm:"column:otp_secret"`
	CreatedAt    time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime;<-:create"`
	UpdatedAt    time.Time      `json:"updated_at" gorm:"column:updated_at;autoCreateTime;autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at" gorm:"index;column:deleted_at"`
}

func (u *User) TableName() string {
	return "users"
}

func Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func (u *User) BeforeSave(tx *gorm.DB) error {
	HashedPassword, err := Hash(u.Password)
	if err != nil {
		return err
	}
	if u.Password == "" {
		return nil
	}
	u.Password = string(HashedPassword)

	uniqueID, _ := uuid.NewV7()
	u.ID = uniqueID.String()

	return nil
}
