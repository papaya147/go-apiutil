package apiutil

import (
	"fmt"
)

type HTTPError struct {
	Message string `json:"message"`
	Detail  string `json:"detail"`
	Status  int    `json:"status"`
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("%s: %s", e.Message, e.Detail)
}

// NewHTTPError registers a new HTTP error with its message, detail and code and returns the error
func NewHTTPError(message, detail string, code int) error {
	err := HTTPError{
		Message: message,
		Detail:  detail,
		Status:  code,
	}
	return err
}
