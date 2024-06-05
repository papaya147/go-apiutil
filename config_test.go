package apiutil

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type TestConfig struct {
	Arg1 string        `mapstructure:"ARG1"`
	Arg2 int           `mapstructure:"ARG2"`
	Arg3 time.Duration `mapstructure:"ARG3"`
}

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig[TestConfig]("./test.env")
	require.NoError(t, err)
	require.NotEmpty(t, config)
	require.Equal(t, "something", config.Arg1)
	require.Equal(t, 20, config.Arg2)
	require.Equal(t, time.Hour*30, config.Arg3)
}
