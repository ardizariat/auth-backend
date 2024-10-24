package entity

import (
	"time"

	"github.com/google/uuid"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID           string         `json:"id" gorm:"column:id;primaryKey;<-:create"`
	CredentialID string         `json:"credential_id" gorm:"column:credential_id"`
	Name         string         `json:"name" gorm:"column:name"`
	Username     string         `json:"username" gorm:"column:username"`
	Email        string         `json:"email" gorm:"column:email"`
	IsActive     bool           `json:"is_active" gorm:"column:is_active;default:true"`
	Password     string         `json:"-" gorm:"column:password"`
	VerifiedAt   *time.Time     `json:"verified_at" gorm:"column:verified_at"`
	LastLogin    *time.Time     `json:"last_login" gorm:"column:last_login"`
	Pin          *uint16        `json:"pin" gorm:"column:pin"`
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

	credentialID, _ := gonanoid.New()
	u.CredentialID = credentialID

	return nil
}
