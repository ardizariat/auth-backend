package response

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// Meta holds the status and message information for the API response.
type Meta struct {
	Success bool   `json:"success"`
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
}

// Result holds the data and optional pagination information.
type Result[T any] struct {
	Data       T           `json:"data,omitempty"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

// Pagination holds pagination details.
type Pagination struct {
	Page      int `json:"page"`
	Limit     int `json:"limit"`
	TotalRows int `json:"total_rows"`
	TotalPage int `json:"total_page"`
}

// WebResponseSuccess is the main structure for a successful API response.
type WebResponseSuccess[T any] struct {
	Meta   Meta      `json:"meta"`
	Result Result[T] `json:"result"`
}

// ResponseSuccess returns a JSON response for a successful API call.
func ResponseSuccess[T any](ctx *fiber.Ctx, message string, data T, pagination *Pagination) error {
	if message == "" {
		message = http.StatusText(http.StatusOK)
	}
	response := WebResponseSuccess[T]{
		Meta: Meta{
			Success: true,
			Status:  http.StatusOK,
			Message: message,
		},
		Result: Result[T]{
			Data:       data,
			Pagination: pagination,
		},
	}

	return ctx.Status(http.StatusOK).JSON(response)
}
