package apiutil

import (
	"github.com/stretchr/testify/require"
	"testing"
)

type testRequest struct {
	Name string `json:"name" validate:"required,len=4"`
	Age  int    `json:"age" validate:"required,max=18"`
}

func TestValidateRequest(t *testing.T) {
	arg := testRequest{
		Name: "abhi",
		Age:  18,
	}
	err := ValidateRequest(arg)
	require.NoError(t, err)

	arg = testRequest{
		Name: "abhinav",
		Age:  22,
	}
	err = ValidateRequest(arg)
	require.Error(t, err)
}
