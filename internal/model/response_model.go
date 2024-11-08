package model

type WebResponse[T any] struct {
	Data    T             `json:"data,omitempty"`
	Paging  *PageMetadata `json:"paging,omitempty"`
	Errors  any           `json:"errors,omitempty"`
	Message string        `json:"message,omitempty"`
}

type PageResponse[T any] struct {
	Data         []T          `json:"data,omitempty"`
	PageMetadata PageMetadata `json:"paging,omitempty"`
}

type PageMetadata struct {
	Page      int   `json:"page"`
	Size      int   `json:"size"`
	TotalItem int64 `json:"total_item"`
	TotalPage int64 `json:"total_page"`
}

type Meta struct {
	Success bool   `json:"success"`
	Status  uint16 `json:"status"`
	Message string `json:"message,omitempty"`
}

type Result[T any] struct {
	Data       []T         `json:"data,omitempty"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

type Pagination struct {
	Page      int `json:"page"`
	Limit     int `json:"limit"`
	TotalRows int `json:"total_rows"`
	TotalPage int `json:"total_page"`
}

type WebResponseSuccess[T any] struct {
	Meta   *Meta      `json:"meta,omitempty"`
	Result *Result[T] `json:"result,omitempty"`
}
