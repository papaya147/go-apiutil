package apiutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"net/http"
)

var maxBytes = 10 << 20

// SetMaxBytes sets the maximum number of bytes allowed in the request body. Default is 10485760.
func SetMaxBytes(mb int) {
	maxBytes = mb
}

// ReadJson reads a json request body into the specified struct. The maximum read bytes is defined by `maxBytes`.
func ReadJson[I any](w http.ResponseWriter, r *http.Request) (I, error) {
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	var out I
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("error decoding json: %s", err)
	}

	if err := dec.Decode(&struct{}{}); err != nil {
		return out, errors.New("json body must contain only one object")
	}

	return out, nil
}

// ReadJsonAndValidate reads a json request body into the specified struct and validates it. The maximum read bytes is defined by `maxBytes`.
// The customValidators parameter is a map of field name to custom validation function.
func ReadJsonAndValidate[I any](w http.ResponseWriter, r *http.Request, customValidatorsSlice ...map[string]func(p validator.FieldLevel) bool) (I, error) {
	data, err := ReadJson[I](w, r)
	if err != nil {
		return data, err
	}

	return data, ValidateRequest(data, customValidatorsSlice...)
}

// WriteJson writes a json response with the specified status and data.
func WriteJson(w http.ResponseWriter, status int, data any, headers ...http.Header) {
	out, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("error marshalling data: %s", err)
		return
	}

	if len(headers) > 0 {
		for key, value := range headers[0] {
			w.Header()[key] = value
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(out)
	if err != nil {
		fmt.Printf("error writing response: %s", err)
	}
}

// ErrorJson writes a json response with the specified error. A non HTTPError type will follow:
//   - Status: 400
//   - Message: "bad request"
//   - Detail: error.Error()
func ErrorJson(w http.ResponseWriter, err error) {
	var httpErr HTTPError
	if !errors.As(err, &httpErr) {
		httpErr.Message = "bad request"
		httpErr.Status = http.StatusBadRequest
		httpErr.Detail = err.Error()
	}
	WriteJson(w, httpErr.Status, httpErr)
}
