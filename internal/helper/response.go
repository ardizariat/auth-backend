package helper

import (
	"net/http"
)

// Meta defines metadata for the HTTP response
type Meta struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// HttpResponse defines a generic HTTP response structure
type HttpResponseSuccess[T any] struct {
	Meta   Meta `json:"meta"`
	Result T    `json:"result"`
}

type HttpResponseParamSuccess[T any] struct {
	StatusCode int
	Message    string
	Data       T
}

// NewHttpResponse creates a new instance of HttpResponse with provided data, message, and status code
func ResponseSuccess[T any](res HttpResponseParamSuccess[T]) *HttpResponseSuccess[T] {
	if res.StatusCode == 0 {
		res.StatusCode = http.StatusOK
	}
	if res.Message == "" {
		res.Message = http.StatusText(res.StatusCode)
	}
	// Create an instance of HttpResponse with the appropriate meta and result
	resp := &HttpResponseSuccess[T]{
		Meta: Meta{
			Status:  res.StatusCode,
			Message: res.Message,
			Success: true,
		},
		Result: res.Data,
	}

	// Return the response as JSON
	return resp
}

// HttpResponse defines a generic HTTP response structure
type HttpResponseError[T any] struct {
	Meta   Meta `json:"meta"`
	Errors T    `json:"errors,omitempty"`
}

type HttpResponseParamError[T any] struct {
	StatusCode int
	Message    string
	Errors     T
}

// NewHttpResponse creates a new instance of HttpResponse with provided data, message, and status code
func ResponseError[T any](res HttpResponseParamError[T]) *HttpResponseError[T] {
	if res.StatusCode == 0 {
		res.StatusCode = http.StatusInternalServerError
	}
	if res.Message == "" {
		res.Message = http.StatusText(http.StatusInternalServerError)
	}
	// Create an instance of HttpResponse with the appropriate meta and result
	resp := &HttpResponseError[T]{
		Meta: Meta{
			Status:  res.StatusCode,
			Message: res.Message,
			Success: false,
		},
		Errors: res.Errors,
	}

	// Return the response as JSON
	return resp
}
