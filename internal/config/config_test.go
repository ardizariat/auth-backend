package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestViper(t *testing.T) {
	viperConfig := NewViper()
	logger := NewLogger(viperConfig)
	database := NewDatabase(viperConfig, logger)
	client := NewRedis(viperConfig)
	jwtWrapper := NewJwtWrapper(viperConfig)
	assert.NotNil(t, viperConfig)
	assert.NotNil(t, logger)
	assert.NotNil(t, database)
	assert.NotNil(t, client)
	assert.NotNil(t, jwtWrapper)
}
