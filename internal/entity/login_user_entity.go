package entity

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type LoginUser struct {
	ID            string    `json:"id" gorm:"column:id;primaryKey;<-:create"`
	UserID        string    `json:"user_id" gorm:"column:user_id"`
	UserAgent     string    `json:"user_agent" gorm:"column:user_agent"`
	IpAddress     string    `json:"ip_address" gorm:"column:ip_address"`
	FirebaseToken *string   `json:"firebase_token" gorm:"column:firebase_token"`
	Model         *string   `json:"model" gorm:"column:model"`
	RefreshToken  *string   `json:"refresh_token" gorm:"column:refresh_token"`
	CreatedAt     time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime;<-:create"`
	UpdatedAt     time.Time `json:"updated_at" gorm:"column:updated_at;autoCreateTime;autoUpdateTime"`
}

func (u *LoginUser) TableName() string {
	return "login_user"
}

func (u *LoginUser) BeforeSave(tx *gorm.DB) error {
	uniqueID, _ := uuid.NewV7()
	u.ID = uniqueID.String()
	return nil
}
