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

var errorMap map[HTTPError]int

func init() {
	errorMap = make(map[HTTPError]int)
}

// RegisterHTTPError registers a new HTTP error with its message, detail and code and returns the error
func RegisterHTTPError(message, detail string, code int) error {
	err := HTTPError{
		Message: message,
		Detail:  detail,
		Status:  code,
	}
	errorMap[err] = code
	return err
}
