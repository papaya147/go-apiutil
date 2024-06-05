package apiutil

import (
	"github.com/spf13/viper"
	"strings"
)

func LoadConfig[I any](path string) (I, error) {
	pathParts := strings.Split(path, "/")
	fileName := pathParts[len(pathParts)-1]
	fileNameParts := strings.Split(fileName, ".")
	fileExt := fileNameParts[len(fileNameParts)-1]
	fileName = strings.Join(fileNameParts[:len(fileNameParts)-1], ".")
	path = strings.Join(pathParts[:len(pathParts)-1], "/")

	viper.AddConfigPath(path)
	viper.SetConfigName(fileName)
	viper.SetConfigType(fileExt)

	viper.AutomaticEnv()

	var config I
	err := viper.ReadInConfig()
	if err != nil {
		return config, err
	}

	err = viper.Unmarshal(&config)
	return config, err
}
