package repository

import (
	"arch/internal/entity"
	"fmt"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type ClientRepository struct {
	Repository[entity.Client]
	Log *logrus.Logger
}

func NewClientRepository(log *logrus.Logger) *ClientRepository {
	return &ClientRepository{
		Log: log,
	}
}

func (r *ClientRepository) GetAll(database *gorm.DB) ([]entity.Client, error) {
	var clients []entity.Client
	err := database.Find(&clients).Order("id DESC").Error
	if err != nil {
		return nil, err
	}
	return clients, nil
}

func (r *ClientRepository) CountClientByColumn(database *gorm.DB, column, name string) (int64, error) {
	var count int64
	columnName := fmt.Sprintf("%s = ?", column)
	if err := database.Table("clients").
		Where(columnName, name).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *ClientRepository) FindByName(database *gorm.DB, entity *entity.Client, id string) error {
	return database.Where("name = ? AND deleted_at IS NULL", id).Take(&entity).Error
}
