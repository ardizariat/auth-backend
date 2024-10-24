package repository

import (
	"gorm.io/gorm"
)

type Repository[T any] struct {
	Database *gorm.DB
}

func (r *Repository[T]) GetAll(database *gorm.DB, entity *[]T) error {
	var count int64
	err := database.Model(&entity).Count(&count).Error
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	return database.Find(&entity).Error
}

func (r *Repository[T]) Create(database *gorm.DB, entity *T) error {
	return database.Create(entity).Error
}

func (r *Repository[T]) Update(database *gorm.DB, entity *T) error {
	return database.Save(entity).Error
}

func (r *Repository[T]) FindById(database *gorm.DB, entity *T, id any) error {
	return database.Where("id = ? AND deleted_at IS NULL", id).Take(&entity).Error
}

func (r *Repository[T]) Delete(database *gorm.DB, entity *T, id any) error {
	return database.Where("id = ? AND deleted_at IS NULL", id).Delete(entity).Error
}
