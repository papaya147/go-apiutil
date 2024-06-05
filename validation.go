package apiutil

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"net/http"
	"reflect"
	"strings"
)

type validationErrors []string

// ValidateRequest validates the request payload using the Go Playground Validator.
// Use the `validate` tag on the struct fields to specify the validation rules.
// The customValidators map can be used to register custom validation rules.
func ValidateRequest(requestPayload any, customValidatorsSlice ...map[string]func(level validator.FieldLevel) bool) error {
	validate := validator.New()

	customValidators := make(map[string]func(level validator.FieldLevel) bool)
	for _, customValidators := range customValidatorsSlice {
		for key, val := range customValidators {
			customValidators[key] = val
		}
	}
	for key, val := range customValidators {
		if err := validate.RegisterValidation(key, val); err != nil {
			return err
		}
	}

	err := validate.Struct(requestPayload)
	if err != nil {
		var invalidValidationError *validator.InvalidValidationError
		if errors.As(err, &invalidValidationError) {
			return errors.New("invalid json")
		}

		var errs validationErrors
		var param string
		for _, err := range err.(validator.ValidationErrors) {
			param = fmt.Sprintf("%s: %s", err.Tag(), err.Param())
			if err.Param() == "" {
				param = err.Tag()
			}
			jsonTag := getJsonTag(requestPayload, err.Field())
			errs = append(errs, fmt.Sprintf("field: %s, expected %s", jsonTag, param))
		}
		return NewHTTPError("bad input", strings.Join(errs, ", "), http.StatusBadRequest)
	}

	return nil
}

func getJsonTag(structure any, fieldName string) string {
	val := reflect.ValueOf(structure)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	typ := val.Type()
	field, found := typ.FieldByName(fieldName)
	if !found {
		return fieldName
	}

	tag := field.Tag.Get("json")
	if tag == "" {
		return fieldName
	}

	tagParts := strings.Split(tag, ",")
	return tagParts[0]
}
