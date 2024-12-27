package entity

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Employee struct {
	ID           string         `json:"id" gorm:"column:id;primaryKey;<-:create"`
	UserID       string         `json:"user_id" gorm:"column:user_id;<-:create"`
	FirstName    string         `json:"first_name" gorm:"column:first_name"`
	LastName     string         `json:"last_name" gorm:"column:last_name"`
	Gender       *string        `json:"gender" gorm:"column:gender"`
	NIP          *string        `json:"nip" gorm:"column:nip"`
	PhoneNumber  *string        `json:"phone_number" gorm:"column:phone_number"`
	JoinDate     *time.Time     `json:"join_date" gorm:"column:join_date"`
	PlaceOfBirth *string        `json:"place_of_birth" gorm:"column:place_of_birth"`
	DateOfBirth  *time.Time     `json:"date_of_birth" gorm:"column:date_of_birth"`
	Address      *string        `json:"address" gorm:"column:address"`
	CreatedAt    time.Time      `json:"created_at" gorm:"column:created_at;autoCreateTime;<-:create"`
	UpdatedAt    time.Time      `json:"updated_at" gorm:"column:updated_at;autoCreateTime;autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at" gorm:"index;column:deleted_at"`
}

func (u *Employee) TableName() string {
	return "employees"
}

func (u *Employee) BeforeSave(tx *gorm.DB) error {
	uniqueID, _ := uuid.NewV7()
	u.ID = uniqueID.String()
	return nil
}
