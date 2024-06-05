package apiutil

import (
	"fmt"
	"github.com/papaya147/randomize"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewHTTPError(t *testing.T) {
	httpError, err := randomize.Do[HTTPError]()
	require.NoError(t, err)
	require.NotEmpty(t, httpError)
	require.Equal(t, httpError.Error(), fmt.Sprintf("%s: %s", httpError.Message, httpError.Detail))
}
