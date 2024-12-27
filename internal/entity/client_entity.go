package entity

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Client struct {
	ID          string         `json:"id" gorm:"column:id;primaryKey;<-:create"`
	Name        string         `json:"name" gorm:"column:name"`
	Enabled     bool           `json:"enabled" gorm:"column:enabled"`
	BaseURL     string         `json:"base_url" gorm:"column:base_url"`
	CallbackURL string         `json:"callback_url" gorm:"column:callback_url"`
	Description *string        `json:"description" gorm:"column:description"`
	CreatedAt   time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime;<-:create"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"column:updated_at;autoCreateTime;autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index;column:deleted_at"`
}

func (u *Client) TableName() string {
	return "clients"
}

func (u *Client) BeforeSave(tx *gorm.DB) error {
	uniqueID, _ := uuid.NewV7()
	u.ID = uniqueID.String()
	return nil
}
