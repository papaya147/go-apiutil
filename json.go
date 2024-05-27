package apiutil

import (
	"encoding/json"
	"errors"
	"fmt"
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
	if err := dec.Decode(out); err != nil {
		return out, fmt.Errorf("error decoding json: %s", err)
	}

	if err := dec.Decode(&struct{}{}); err != nil {
		return out, errors.New("json body must contain only one object")
	}

	return out, nil
}

// WriteJson writes a json response with the specified status and data.
func WriteJson(w http.ResponseWriter, status int, data any, headers ...http.Header) error {
	out, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshalling data: %s", err)
	}

	if len(headers) > 0 {
		for key, value := range headers[0] {
			w.Header()[key] = value
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(out)
	return fmt.Errorf("error writing response: %s", err)
}

// ErrorJson writes a json response with the specified error. A non HTTPError type will follow:
//   - Status: 400
//   - Message: error.Error()
//   - Detail: ""
func ErrorJson(w http.ResponseWriter, err error) error {
	httpErr, ok := err.(HTTPError)
	if !ok {
		httpErr.Message = err.Error()
		httpErr.Status = http.StatusBadRequest
		httpErr.Detail = ""
	}
	return WriteJson(w, httpErr.Status, httpErr)
}
